/**
 * YapID — Avatar Generation Routes
 *
 * Generates deterministic, seed-based SVG avatars entirely server-side.
 * No external services or libraries are required — all styles are custom
 * implementations using geometric shapes and HSL colour generation.
 *
 * Available styles:
 *  - shapes    — overlapping circles, rectangles, and triangles (default)
 *  - identicon — GitHub-style symmetric pixel grid
 *  - geometric — polygon constellations
 *  - pixel     — 8×8 pixel art
 *
 * Avatars are keyed by a short hex seed (avatar_seed column in accounts).
 * The seed is public — it never contains or reveals the wallet address or
 * account ID.
 *
 * GET /avatar/:seed           — serve an SVG avatar
 * GET /avatar/info/styles     — list available style names
 *
 * @module routes/avatar
 * @license BSL-1.1
 */

import { Router }     from 'express';
import { createHash } from 'crypto';

export const avatarRouter = Router();

// ---------------------------------------------------------------------------
// Style registry
// ---------------------------------------------------------------------------

const STYLES = {
  shapes:    generateShapes,
  identicon: generateIdenticon,
  geometric: generateGeometric,
  pixel:     generatePixel,
};

// ---------------------------------------------------------------------------
// GET /avatar/info/styles
// ---------------------------------------------------------------------------

/** Returns the list of available avatar style identifiers. */
avatarRouter.get('/info/styles', (_req, res) => {
  res.json({ styles: Object.keys(STYLES) });
});

// ---------------------------------------------------------------------------
// GET /avatar/:seed
// ---------------------------------------------------------------------------

/**
 * Serves a deterministic SVG avatar for the given seed.
 *
 * Query parameters:
 *  - style {string} — one of the keys in STYLES (default: "shapes")
 *  - size  {number} — output size in pixels, capped at 200 (default: 80)
 *
 * The response carries a 1-year immutable cache header because the same
 * seed always produces the same SVG.
 */
avatarRouter.get('/:seed', (req, res) => {
  const { seed }  = req.params;
  const style     = req.query.style || 'shapes';
  const size      = Math.min(parseInt(req.query.size, 10) || 80, 200);

  // Only accept lowercase hex seeds between 8 and 64 characters
  if (!seed || !/^[a-f0-9]{8,64}$/.test(seed)) {
    return res.status(400).json({ error: 'Invalid seed — must be a hex string of 8–64 characters' });
  }

  const generator = STYLES[style] ?? STYLES.shapes;
  const svg       = generator(seed, size);

  res.setHeader('Content-Type',                  'image/svg+xml');
  res.setHeader('Cache-Control',                 'public, max-age=31536000, immutable');
  res.setHeader('Cross-Origin-Resource-Policy',  'cross-origin');
  res.send(svg);
});

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * Derives `count` deterministic unsigned 32-bit integers from a seed.
 * Each integer is derived by hashing `seed + index` with SHA-256.
 *
 * @param {string} seed
 * @param {number} count
 * @returns {number[]}
 */
function seedToNumbers(seed, count) {
  const numbers = [];
  for (let i = 0; i < count; i++) {
    const hash = createHash('sha256').update(seed + i).digest('hex');
    numbers.push(parseInt(hash.slice(0, 8), 16));
  }
  return numbers;
}

/**
 * Derives a deterministic HSL colour from a seed at a given index slot.
 *
 * @param {string} seed
 * @param {number} index        - Which number slot to use for the hue
 * @param {number} [saturation] - Saturation percentage (default 70)
 * @param {number} [lightness]  - Lightness percentage (default 55)
 * @returns {string} CSS hsl() string
 */
function hslColor(seed, index, saturation = 70, lightness = 55) {
  const hue = seedToNumbers(seed, index + 1)[index] % 360;
  return `hsl(${hue},${saturation}%,${lightness}%)`;
}

// ---------------------------------------------------------------------------
// Style: shapes
// ---------------------------------------------------------------------------

/**
 * Generates an avatar composed of 6 semi-transparent overlapping shapes
 * (circles, rounded rectangles, and triangles) on a dark background.
 *
 * @param {string} seed
 * @param {number} size
 * @returns {string} SVG markup
 */
function generateShapes(seed, size) {
  const nums       = seedToNumbers(seed, 20);
  const background = hslColor(seed, 0, 60, 15);
  const colors     = [
    hslColor(seed, 1, 80, 65),
    hslColor(seed, 2, 70, 55),
    hslColor(seed, 3, 90, 70),
  ];

  const shapes = [];

  for (let i = 0; i < 6; i++) {
    const x       = nums[i * 3]       % size;
    const y       = nums[i * 3 + 1]   % size;
    const radius  = 10 + (nums[i * 3 + 2] % 30);
    const color   = colors[i % 3];
    const opacity = (0.5 + (nums[i] % 5) * 0.1).toFixed(2);
    const type    = nums[i] % 3;

    if (type === 0) {
      shapes.push(
        `<circle cx="${x}" cy="${y}" r="${radius}" fill="${color}" opacity="${opacity}"/>`
      );
    } else if (type === 1) {
      shapes.push(
        `<rect x="${x - radius / 2}" y="${y - radius / 2}" ` +
        `width="${radius}" height="${radius}" ` +
        `fill="${color}" opacity="${opacity}" rx="${(radius * 0.2).toFixed(1)}"/>`
      );
    } else {
      const points = `${x},${y - radius} ${x + radius},${y + radius} ${x - radius},${y + radius}`;
      shapes.push(
        `<polygon points="${points}" fill="${color}" opacity="${opacity}"/>`
      );
    }
  }

  const rx = (size * 0.15).toFixed(1);

  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">` +
    `<rect width="${size}" height="${size}" fill="${background}"/>` +
    `<clipPath id="c"><rect width="${size}" height="${size}" rx="${rx}"/></clipPath>` +
    `<g clip-path="url(#c)">${shapes.join('')}</g>` +
    `</svg>`
  );
}

// ---------------------------------------------------------------------------
// Style: identicon
// ---------------------------------------------------------------------------

/**
 * Generates a symmetric 5×5 pixel identicon (similar to GitHub avatars).
 * The left half is mirrored to the right, producing a recognisable pattern.
 *
 * @param {string} seed
 * @param {number} size
 * @returns {string} SVG markup
 */
function generateIdenticon(seed, size) {
  const hash       = createHash('sha256').update(seed).digest('hex');
  const foreground = `#${hash.slice(0, 6)}`;
  const background = '#1a1a2e';
  const GRID       = 5;
  const cellSize   = Math.floor(size / GRID);
  const rects      = [];

  for (let row = 0; row < GRID; row++) {
    for (let col = 0; col < Math.ceil(GRID / 2); col++) {
      const idx = row * Math.ceil(GRID / 2) + col;
      if (parseInt(hash[idx], 16) % 2 === 0) continue;

      const x1 = col * cellSize;
      const x2 = (GRID - 1 - col) * cellSize;

      rects.push(
        `<rect x="${x1}" y="${row * cellSize}" width="${cellSize}" height="${cellSize}" fill="${foreground}"/>`
      );
      if (x1 !== x2) {
        rects.push(
          `<rect x="${x2}" y="${row * cellSize}" width="${cellSize}" height="${cellSize}" fill="${foreground}"/>`
        );
      }
    }
  }

  const rx = (size * 0.1).toFixed(1);

  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">` +
    `<rect width="${size}" height="${size}" fill="${background}" rx="${rx}"/>` +
    rects.join('') +
    `</svg>`
  );
}

// ---------------------------------------------------------------------------
// Style: geometric
// ---------------------------------------------------------------------------

/**
 * Generates an avatar from 8 coloured polygon shapes arranged around the
 * centre point using deterministic angles derived from the seed.
 *
 * @param {string} seed
 * @param {number} size
 * @returns {string} SVG markup
 */
function generateGeometric(seed, size) {
  const nums       = seedToNumbers(seed, 12);
  const background = hslColor(seed, 0, 50, 10);
  const half       = size / 2;
  const polygons   = [];

  for (let i = 0; i < 8; i++) {
    const angle  = (nums[i] % 360) * (Math.PI / 180);
    const radius = 15 + (nums[i] % (half - 20));
    const cx     = half + Math.cos(angle) * (nums[i + 1] % (half * 0.6));
    const cy     = half + Math.sin(angle) * (nums[i + 1] % (half * 0.6));
    const sides  = 3 + (nums[i] % 4);
    const color  = hslColor(seed, i + 1, 80, 60);
    const points = [];

    for (let s = 0; s < sides; s++) {
      const a = (s / sides) * 2 * Math.PI + angle;
      points.push(`${cx + Math.cos(a) * radius},${cy + Math.sin(a) * radius}`);
    }

    polygons.push(
      `<polygon points="${points.join(' ')}" fill="${color}" opacity="0.6"/>`
    );
  }

  const rx = (size * 0.12).toFixed(1);

  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">` +
    `<rect width="${size}" height="${size}" fill="${background}" rx="${rx}"/>` +
    `<clipPath id="clip"><rect width="${size}" height="${size}" rx="${rx}"/></clipPath>` +
    `<g clip-path="url(#clip)">${polygons.join('')}</g>` +
    `</svg>`
  );
}

// ---------------------------------------------------------------------------
// Style: pixel
// ---------------------------------------------------------------------------

/**
 * Generates an 8×8 pixel art avatar.  Each cell is filled based on a
 * threshold applied to the hex characters of the seed's SHA-256 hash.
 *
 * @param {string} seed
 * @param {number} size
 * @returns {string} SVG markup
 */
function generatePixel(seed, size) {
  const hash       = createHash('sha256').update(seed).digest('hex');
  const foreground = hslColor(seed, 0, 75, 60);
  const background = hslColor(seed, 1, 30, 12);
  const GRID       = 8;
  const cellSize   = size / GRID;
  const rects      = [];

  for (let row = 0; row < GRID; row++) {
    for (let col = 0; col < GRID; col++) {
      const idx = (row * GRID + col) % hash.length;
      if (parseInt(hash[idx], 16) > 7) continue;
      rects.push(
        `<rect x="${col * cellSize}" y="${row * cellSize}" ` +
        `width="${cellSize}" height="${cellSize}" fill="${foreground}"/>`
      );
    }
  }

  const rx = (size * 0.08).toFixed(1);

  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" ` +
    `xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges">` +
    `<rect width="${size}" height="${size}" fill="${background}" rx="${rx}"/>` +
    rects.join('') +
    `</svg>`
  );
}
