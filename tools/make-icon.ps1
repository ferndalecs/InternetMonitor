# Draws the application icon (a pulse line on a blue tile) and saves it as a multi-size .ico.
param([string]$OutFile = (Join-Path $PSScriptRoot '..\src\app.ico'))

Add-Type -AssemblyName System.Drawing

$sizes = 16, 24, 32, 48, 64, 256
$pngs = @()

foreach ($size in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)

    # rounded tile
    $r = [single]($size * 0.22)
    $d = $r * 2
    $w = [single]($size - 1)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($w - $d, 0, $d, $d, 270, 90)
    $path.AddArc($w - $d, $w - $d, $d, $d, 0, 90)
    $path.AddArc(0, $w - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $rect = New-Object System.Drawing.RectangleF 0, 0, $size, $size
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, ([System.Drawing.Color]::FromArgb(0x2A, 0x78, 0xD6)), ([System.Drawing.Color]::FromArgb(0x10, 0x28, 0x3F)), 60
    $g.FillPath($brush, $path)

    # pulse line
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([single][Math]::Max(1.6, $size * 0.085))
    $pen.LineJoin = 'Round'; $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $pts = @(
        @(0.14, 0.55), @(0.33, 0.55), @(0.43, 0.27), @(0.57, 0.76), @(0.66, 0.55), @(0.86, 0.55)
    ) | ForEach-Object { New-Object System.Drawing.PointF ([single]($_[0] * $size)), ([single]($_[1] * $size)) }
    $g.DrawLines($pen, [System.Drawing.PointF[]]$pts)

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += , $ms.ToArray()
    $g.Dispose(); $bmp.Dispose()
}

# ICO container holding PNG-compressed images
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter $out
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$pngs[$i].Length); $bw.Write([uint32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($OutFile, $out.ToArray())
Write-Host "Icon written: $OutFile"
