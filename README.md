# Vercel Deployment Guide

## Prerequisites
1. GitHub account
2. Vercel account (free)
3. This repository pushed to GitHub

## Deployment Steps

### 1. Push to GitHub
```bash
git add .
git commit -m "Prepare for Vercel deployment"
git push origin main
```

### 2. Deploy to Vercel
1. Go to [vercel.com](https://vercel.com)
2. Sign in with GitHub
3. Click "New Project"
4. Import your GitHub repository
5. Vercel will auto-detect it's a Python project
6. Click "Deploy"

### 3. Configuration
- **Framework Preset**: Other
- **Build Command**: (leave empty)
- **Output Directory**: (leave empty)
- **Install Command**: pip install -r requirements.txt

## Auto-Deployment
- Every push to `main` branch automatically redeploys
- Policy file updates: Add files to `POLICY_ID/` folder and push
- Deployment takes ~2-3 minutes

## File Structure for Vercel
```
├── api/
│   ├── index.py          # Vercel entry point (main Flask app)
│   ├── policy_matcher.py # Core logic
│   ├── requirements.txt  # Python dependencies
│   ├── POLICY_ID/        # Policy files (deployed as static)
│   └── templates/        # HTML templates
├── vercel.json          # Vercel configuration
├── runtime.txt          # Python version
└── .vercelignore        # Files to exclude
```

## Adding New Policy Files
1. Add files to `api/POLICY_ID/` folder locally
2. Commit and push to GitHub
3. Vercel automatically redeploys with new files
4. Files available in ~2-3 minutes

## Environment Variables (if needed)
Set in Vercel dashboard under Project Settings > Environment Variables

## Troubleshooting
- Check Vercel deployment logs for errors
- Ensure all files are committed to Git
- Policy files must be in `POLICY_ID/` folder
- Max file size: 16MB per upload