import AppKit
import CoreGraphics
import Foundation

// Renders the secretctl mark as an app icon set.
//
// The mark is a split ring — two thick arcs with gaps on the horizontal axis —
// around a solid centre node, with a green bar leaving the node to the right.
// It is drawn rather than traced from a bitmap so it stays crisp at 16pt, where
// a downsampled PNG turns to mush.

let ink = CGColor(red: 0.106, green: 0.114, blue: 0.122, alpha: 1)   // #1B1D1F
let accent = CGColor(red: 0.071, green: 0.914, blue: 0.545, alpha: 1) // #12E98B

/// Draw the mark into `context` on a unit canvas of `size`, y-down.
func drawMark(in context: CGContext, size: CGFloat, background: CGColor?) {
    if let background {
        context.setFillColor(background)
        context.fill(CGRect(x: 0, y: 0, width: size, height: size))
    }

    // Work in a 1024 design space, then scale.
    let s = size / 1024
    context.saveGState()
    context.scaleBy(x: s, y: s)

    let cx: CGFloat = 512, cy: CGFloat = 512
    let ringRadius: CGFloat = 300      // mid-line of the stroke
    let ringWidth: CGFloat = 108
    let nodeRadius: CGFloat = 128
    let gapHalf: CGFloat = 17          // half the angular gap, degrees
    // The gap axis sits a few degrees off horizontal, which is what stops the
    // mark reading as a plain broken circle.
    let ringTilt: CGFloat = -5

    func radians(_ degrees: CGFloat) -> CGFloat { degrees * .pi / 180 }

    // The context is y-down, so an angle measured clockwise from +x puts 270°
    // at the top of the canvas.
    context.setStrokeColor(ink)
    context.setLineWidth(ringWidth)
    // Butt caps, not round: a round cap projects half the stroke width past the
    // arc's end, which at this thickness swallows most of the gap.
    context.setLineCap(.butt)

    context.saveGState()
    context.translateBy(x: cx, y: cy)
    context.rotate(by: radians(ringTilt))
    context.translateBy(x: -cx, y: -cy)

    // Upper arc: left gap edge, over the top, to the right gap edge.
    context.addArc(center: CGPoint(x: cx, y: cy), radius: ringRadius,
                   startAngle: radians(180 + gapHalf), endAngle: radians(360 - gapHalf),
                   clockwise: false)
    context.strokePath()

    // Lower arc: mirrored under the bottom.
    context.addArc(center: CGPoint(x: cx, y: cy), radius: ringRadius,
                   startAngle: radians(gapHalf), endAngle: radians(180 - gapHalf),
                   clockwise: false)
    context.strokePath()
    context.restoreGState()

    // The bar bridges the node to the ring line and stops exactly there,
    // leaving through the gap. Drawn before the node so their meeting edge
    // stays a clean circle.
    let barInset: CGFloat = 22
    let barHeight: CGFloat = 78
    let barStart = cx + nodeRadius - barInset
    let barEnd = cx + ringRadius - ringWidth / 2
    context.setFillColor(accent)
    context.fill(CGRect(x: barStart, y: cy - barHeight / 2,
                        width: barEnd - barStart, height: barHeight))

    context.setFillColor(ink)
    context.addArc(center: CGPoint(x: cx, y: cy), radius: nodeRadius,
                   startAngle: 0, endAngle: radians(360), clockwise: false)
    context.fillPath()

    context.restoreGState()
}

func render(size: Int, background: CGColor?, cornerFraction: CGFloat = 0) -> Data {
    let dimension = CGFloat(size)
    let space = CGColorSpaceCreateDeviceRGB()
    guard let context = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else { fatalError("could not create context") }

    context.setShouldAntialias(true)
    context.interpolationQuality = .high

    if background != nil && cornerFraction > 0 {
        let radius = dimension * cornerFraction
        let path = CGPath(roundedRect: CGRect(x: 0, y: 0, width: dimension, height: dimension),
                          cornerWidth: radius, cornerHeight: radius, transform: nil)
        context.addPath(path)
        context.clip()
    }

    drawMark(in: context, size: dimension, background: background)

    guard let image = context.makeImage() else { fatalError("could not render") }
    let representation = NSBitmapImageRep(cgImage: image)
    guard let png = representation.representation(using: .png, properties: [:]) else {
        fatalError("could not encode PNG")
    }
    return png
}

// ---------------------------------------------------------------------------

let arguments = CommandLine.arguments
let outputDirectory = arguments.count > 1 ? arguments[1] : "."
let white = CGColor(red: 1, green: 1, blue: 1, alpha: 1)

try? FileManager.default.createDirectory(atPath: outputDirectory, withIntermediateDirectories: true)

// The .iconset names macOS expects.
let iconSizes: [(name: String, pixels: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]

for (name, pixels) in iconSizes {
    let data = render(size: pixels, background: white, cornerFraction: 0.2237)
    try data.write(to: URL(fileURLWithPath: "\(outputDirectory)/\(name).png"))
}

// A transparent mark for the onboarding screen and the README.
let markData = render(size: 1024, background: nil)
try markData.write(to: URL(fileURLWithPath: "\(outputDirectory)/../mark.png"))

// Render standard secretctl.png logo
let logoData = render(size: 512, background: nil)
try? logoData.write(to: URL(fileURLWithPath: "\(outputDirectory)/../secretctl.png"))
try? logoData.write(to: URL(fileURLWithPath: "\(outputDirectory)/secretctl.png"))

print("rendered \(iconSizes.count) icon sizes and secretctl.png into \(outputDirectory)")
