# Generates src\NetworkTelemetryInspector\Resources\app.ico with GDI+.
# A rounded blue-to-cyan tile with a white globe (network) and a small "inspector" lens.
# ASCII only: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI.
[CmdletBinding()]
param([string]$PreviewPath)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $root 'src\NetworkTelemetryInspector\Resources\app.ico'
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256

function New-FramePng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [single]$size
    $inset = [single]([Math]::Max(0.5, $s * 0.03))
    $radius = [single]($s * 0.22)
    $rect = New-Object System.Drawing.RectangleF($inset, $inset, ($s - 2 * $inset), ($s - 2 * $inset))
    $d = $radius * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc(($rect.Right - $d), $rect.Y, $d, $d, 270, 90)
    $path.AddArc(($rect.Right - $d), ($rect.Bottom - $d), $d, $d, 0, 90)
    $path.AddArc($rect.X, ($rect.Bottom - $d), $d, $d, 90, 90)
    $path.CloseFigure()

    $top = [System.Drawing.Color]::FromArgb(255, 44, 128, 240)
    $bottom = [System.Drawing.Color]::FromArgb(255, 24, 170, 200)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $top, $bottom, 60)
    $g.FillPath($brush, $path)

    $white = [System.Drawing.Color]::White
    $w = [single]([Math]::Max(1.3, $s * 0.065))
    $pen = New-Object System.Drawing.Pen($white, $w)

    # Globe: centred slightly up-left to leave room for the lens.
    $gr = [single]($s * 0.27)
    $cx = [single]($s * 0.45)
    $cy = [single]($s * 0.45)
    $g.DrawEllipse($pen, ($cx - $gr), ($cy - $gr), (2 * $gr), (2 * $gr))
    if ($size -ge 24) {
        $thin = New-Object System.Drawing.Pen($white, [single]([Math]::Max(1.0, $w * 0.7)))
        $g.DrawEllipse($thin, ($cx - $gr * 0.45), ($cy - $gr), ($gr * 0.9), (2 * $gr))
        $g.DrawLine($thin, ($cx - $gr), $cy, ($cx + $gr), $cy)
    }

    # Lens: a filled white ring at the lower right with a short handle.
    $lr = [single]($s * 0.13)
    $lx = [single]($s * 0.66)
    $ly = [single]($s * 0.66)
    $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 20, 60, 110))
    $g.FillEllipse($fill, ($lx - $lr), ($ly - $lr), (2 * $lr), (2 * $lr))
    $g.DrawEllipse($pen, ($lx - $lr), ($ly - $lr), (2 * $lr), (2 * $lr))
    $handle = New-Object System.Drawing.Pen($white, [single]([Math]::Max(1.5, $s * 0.085)))
    $handle.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $handle.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $off = [single]($lr * 0.72)
    $g.DrawLine($handle, ($lx + $off), ($ly + $off), ($lx + $lr * 1.3), ($ly + $lr * 1.3))

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return , $ms.ToArray()
}

$frames = @{}
foreach ($sz in $sizes) { $frames[$sz] = New-FramePng $sz }

$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]$sizes.Count)
$offset = 6 + (16 * $sizes.Count)
foreach ($sz in $sizes) {
    $data = $frames[$sz]
    $wh = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([Byte]$wh)
    $bw.Write([Byte]$wh)
    $bw.Write([Byte]0)
    $bw.Write([Byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$data.Length)
    $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($sz in $sizes) { $bw.Write($frames[$sz]) }
$bw.Flush()
New-Item -ItemType Directory -Force -Path (Split-Path $outPath) | Out-Null
[System.IO.File]::WriteAllBytes($outPath, $out.ToArray())
$bw.Dispose()
Write-Host "Icon written: $outPath" -ForegroundColor Green

if ($PreviewPath) {
    [System.IO.File]::WriteAllBytes($PreviewPath, $frames[256])
    Write-Host "Preview written: $PreviewPath" -ForegroundColor Green
}
