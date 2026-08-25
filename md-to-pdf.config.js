module.exports = {
  stylesheet: [
    'https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown-light.min.css',
    'https://fonts.googleapis.com/css2?family=Merriweather:wght@300;400;700&family=Open+Sans:wght@300;400;600;700&display=swap'
  ],
  css: `
    body {
      font-family: 'Open Sans', sans-serif !important;
      color: #2D3748;
      line-height: 1.6;
      text-align: justify;
    }
    .markdown-body {
      box-sizing: border-box;
      min-width: 200px;
      max-width: 100%;
      margin: 0 auto;
      padding: 0;
    }
    
    /* Elegant Headings */
    h1, h2, h3, h4 {
      font-family: 'Merriweather', serif !important;
      color: #1A202C;
      margin-top: 1.5em;
      margin-bottom: 0.5em;
    }
    h1 {
      font-size: 2.5em;
      border-bottom: 3px solid #2B6CB0;
      padding-bottom: 0.2em;
      margin-top: 2em;
    }
    h2 {
      font-size: 1.8em;
      border-bottom: 1px solid #E2E8F0;
      padding-bottom: 0.2em;
      color: #2C5282;
    }
    h3 { font-size: 1.4em; color: #2A4365; }
    
    /* Cover Page Styling for the very first h1 */
    h1:first-of-type {
      text-align: center;
      font-size: 3em;
      margin-top: 30vh;
      border-bottom: none;
      color: #1A202C;
    }
    
    /* Subtitle styling for the h2 immediately following the cover h1 */
    h1:first-of-type + h2 {
      text-align: center;
      border-bottom: none;
      font-size: 1.5em;
      color: #4A5568;
      font-weight: 300;
      margin-top: 0.5em;
    }
    
    /* Add a page break after the first few paragraphs if it looks like a title page */
    p:nth-of-type(1) {
      page-break-before: always;
    }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1em;
      margin-bottom: 2em;
      font-size: 0.95em;
    }
    th, td {
      border: 1px solid #CBD5E0;
      padding: 12px 16px;
      text-align: left;
    }
    th {
      background-color: #EDF2F7;
      color: #2D3748;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85em;
      letter-spacing: 0.05em;
    }
    tr:nth-child(even) {
      background-color: #F7FAFC;
    }
    
    /* Code blocks - Clean and neutral */
    pre {
      background-color: #F7FAFC !important;
      color: #2D3748 !important;
      border: 1px solid #E2E8F0;
      border-radius: 6px;
      padding: 16px;
      font-family: monospace;
      font-size: 0.85em;
    }
    code {
      color: #2D3748;
      background-color: #F7FAFC;
      border: 1px solid #E2E8F0;
      padding: 2px 4px;
      border-radius: 4px;
      font-family: monospace;
    }
    pre code {
      border: none;
      padding: 0;
      background-color: transparent;
    }
    
    /* Blockquotes */
    blockquote {
      border-left: 4px solid #3182CE;
      background-color: #EBF8FF;
      padding: 16px;
      margin-left: 0;
      margin-right: 0;
      font-style: italic;
      color: #2B6CB0;
    }
    
    .page-break { page-break-before: always; }
  `,
  pdf_options: {
    format: 'A4',
    margin: { top: '25mm', right: '25mm', bottom: '25mm', left: '25mm' },
    displayHeaderFooter: true,
    headerTemplate: '<div style="font-size: 9px; font-family: \'Open Sans\', sans-serif; width: 100%; text-align: right; padding-right: 25mm; color: #718096; border-bottom: 1px solid #E2E8F0; padding-bottom: 5px;">ReconStrike-ng - Enterprise Security Technical Report</div>',
    footerTemplate: '<div style="font-size: 9px; font-family: \'Open Sans\', sans-serif; width: 100%; display: flex; justify-content: space-between; padding: 0 25mm; color: #A0AEC0;"><span class="date"></span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
  }
};
