# BastCo - Cybersecurity & Software Consultancy

A modern landing page built with Astro and Tailwind CSS v4, featuring a cybersecurity-themed design.

## 🚀 Getting Started

### Prerequisites

- Node.js 18+ 
- pnpm (recommended) or npm

### Installation

```bash
# Install dependencies
pnpm install
# or
npm install
```

### Development

```bash
# Start the dev server
pnpm dev
# or
npm run dev
```

The site will be available at `http://localhost:4321`

### Build

```bash
# Build for production
pnpm build
# or
npm run build
```

### Preview

```bash
# Preview the production build
pnpm preview
# or
npm run preview
```

## 🎨 Features

- **Modern Stack**: Built with Astro 5 and Tailwind CSS v4
- **Cybersecurity Theme**: Dark color scheme with cyan/blue accents
- **Responsive Design**: Mobile-first approach
- **Component-Based**: Modular Astro components
- **Data-Driven**: JSON-based content management
- **Performance**: Optimized for speed and SEO

## 📁 Project Structure

```
/
├── public/              # Static assets
├── src/
│   ├── assets/
│   │   └── css/        # Global styles
│   ├── components/     # Astro components
│   ├── data/           # JSON content files
│   ├── layouts/        # Page layouts
│   └── pages/          # Page routes
├── astro.config.mjs    # Astro configuration
└── package.json
```

## 🎨 Customization

### Colors

Edit `src/assets/css/global.css` to customize the color scheme:

- `--color-bs-primary`: Primary accent color (cyan)
- `--color-bs-surface-*`: Background colors
- `--color-bs-foreground-*`: Text colors

### Content

Update content in `src/data/` JSON files:

- `global_settings.json`: Site-wide settings
- `home.json`: Homepage content
- `services.json`: Services section
- `opensource.json`: Open source projects

## 📝 License

Copyright © 2025 BastCo LLC. All rights reserved.
