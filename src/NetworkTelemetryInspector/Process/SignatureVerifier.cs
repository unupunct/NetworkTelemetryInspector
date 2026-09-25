using System.Runtime.InteropServices;
using NetworkTelemetryInspector.Models;

namespace NetworkTelemetryInspector.Processes;

/// <summary>
/// Authenticode verification via WinVerifyTrust, covering both embedded signatures and
/// catalog signatures (most Windows binaries such as svchost.exe are catalog signed, and a
/// file-only check would wrongly call them unsigned).
///
/// Revocation checking is disabled and URL retrieval is cache-only, so verifying a signature
/// never makes a network request — this is a local, privacy-first tool.
/// </summary>
public static unsafe class SignatureVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint signerIdx, bool counterSigner, uint counterSignerIdx);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string? hashAlg, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint cbHash, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] hash, uint cbHash, uint flags, IntPtr prevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);

    [DllImport("wintrust.dll")]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CertGetNameString(IntPtr pCertContext, uint type, uint flags, IntPtr typePara, char* name, uint cchName);

    public sealed record Result(SignatureStatus Status, string? Signer, bool Catalog);

    public static Result Verify(string path)
    {
        try
        {
            if (!File.Exists(path)) return new Result(SignatureStatus.Unavailable, null, false);
            var embedded = VerifyFile(path);
            if (embedded.Status == SignatureStatus.Valid) return embedded;
            if (embedded.Status == SignatureStatus.Unsigned)
            {
                // Newer catalogs are SHA-256, older ones SHA-1 (null = the default provider).
                var cat = VerifyCatalog(path, "SHA256") ?? VerifyCatalog(path, null);
                if (cat is not null) return cat;
            }
            return embedded;
        }
        catch
        {
            return new Result(SignatureStatus.Unavailable, null, false);
        }
    }

    private static Result VerifyFile(string path)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)sizeof(WINTRUST_FILE_INFO), pcwszFilePath = pathPtr };
        var filePtr = Marshal.AllocHGlobal(sizeof(WINTRUST_FILE_INFO));
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            return Run(WTD_CHOICE_FILE, filePtr, catalog: false);
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    private static Result? VerifyCatalog(string path, string? hashAlgorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0)) return null;
        IntPtr catInfo = IntPtr.Zero;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var handle = fs.SafeFileHandle.DangerousGetHandle();
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
            if (size == 0 || size > 256) return null;
            var hash = new byte[size];
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0)) return null;

            catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero) return null;

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) return null;

            var memberTag = Convert.ToHexString(hash);
            var catPath = Marshal.StringToHGlobalUni(ci.wszCatalogFile);
            var tagPtr = Marshal.StringToHGlobalUni(memberTag);
            var memberPath = Marshal.StringToHGlobalUni(path);
            var hashPtr = Marshal.AllocHGlobal(hash.Length);
            var info = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                Marshal.StructureToPtr(new WINTRUST_CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                    pcwszCatalogFilePath = catPath,
                    pcwszMemberTag = tagPtr,
                    pcwszMemberFilePath = memberPath,
                    hMemberFile = handle,
                    pbCalculatedFileHash = hashPtr,
                    cbCalculatedFileHash = size,
                    hCatAdmin = admin
                }, info, false);
                var r = Run(WTD_CHOICE_CATALOG, info, catalog: true);
                return r.Status == SignatureStatus.Unsigned ? null : r;
            }
            finally
            {
                Marshal.FreeHGlobal(info);
                Marshal.FreeHGlobal(hashPtr);
                Marshal.FreeHGlobal(memberPath);
                Marshal.FreeHGlobal(tagPtr);
                Marshal.FreeHGlobal(catPath);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    private static Result Run(uint unionChoice, IntPtr pInfo, bool catalog)
    {
        var action = GenericVerifyV2;
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)sizeof(WINTRUST_DATA),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pInfo = pInfo,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
        };
        var hr = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        string? signer = null;
        try
        {
            if (data.hWVTStateData != IntPtr.Zero) signer = SignerName(data.hWVTStateData);
        }
        catch { }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
        }

        var status = hr switch
        {
            0 => SignatureStatus.Valid,
            TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unsigned,
            _ => SignatureStatus.Invalid
        };
        return new Result(status, status == SignatureStatus.Unsigned ? null : signer, catalog);
    }

    private static string? SignerName(IntPtr state)
    {
        var prov = WTHelperProvDataFromStateData(state);
        if (prov == IntPtr.Zero) return null;
        var sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if (sgnr == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_SGNR (x64): cbStruct@0, sftVerifyAsOf@4, csCertChain@12, pasCertChain@16
        var count = *(uint*)((byte*)sgnr + 12);
        var chain = *(IntPtr*)((byte*)sgnr + 16);
        if (count == 0 || chain == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_CERT: cbStruct@0, pCert@8
        var cert = *(IntPtr*)((byte*)chain + 8);
        if (cert == IntPtr.Zero) return null;
        var buf = stackalloc char[256];
        var n = CertGetNameString(cert, 4 /* CERT_NAME_SIMPLE_DISPLAY_TYPE */, 0, IntPtr.Zero, buf, 256);
        return n > 1 ? new string(buf, 0, (int)n - 1) : null;
    }
}
