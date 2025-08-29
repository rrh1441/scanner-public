const fs = require('fs');
const path = require('path');

function updateImports(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;
  
  // Replace @/lib/utils with @dealbrief/utils
  if (content.includes('@/lib/utils')) {
    content = content.replace(/@\/lib\/utils/g, '@dealbrief/utils');
    modified = true;
  }
  
  // Replace @/components/ui/ with ./
  if (content.includes('@/components/ui/')) {
    content = content.replace(/@\/components\/ui\//g, './');
    modified = true;
  }
  
  // Replace @/hooks/ with @dealbrief/utils
  if (content.includes('@/hooks/')) {
    content = content.replace(/@\/hooks\/use-mobile/g, '@dealbrief/utils');
    content = content.replace(/@\/hooks\/use-toast/g, '@dealbrief/utils');
    modified = true;
  }
  
  if (modified) {
    fs.writeFileSync(filePath, content);
    console.log(`Updated: ${filePath}`);
  }
}

function processDirectory(dir) {
  const files = fs.readdirSync(dir);
  
  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory() && file !== 'node_modules') {
      processDirectory(filePath);
    } else if (file.endsWith('.ts') || file.endsWith('.tsx')) {
      updateImports(filePath);
    }
  });
}

// Process UI package
console.log('Fixing imports in packages/ui...');
processDirectory(path.join(__dirname, '..', 'packages', 'ui'));

// Process utils package
console.log('Fixing imports in packages/utils...');
processDirectory(path.join(__dirname, '..', 'packages', 'utils'));

console.log('Done!');