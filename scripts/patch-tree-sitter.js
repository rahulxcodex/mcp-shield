const fs = require('fs');
const path = require('path');

const treeSitterIndexPath = path.resolve(__dirname, '../node_modules/tree-sitter/index.js');

if (fs.existsSync(treeSitterIndexPath)) {
  let content = fs.readFileSync(treeSitterIndexPath, 'utf8');
  let modified = false;

  // 1. Preserve native Tree.prototype methods across multiple module evaluations in Jest
  const oldDestructure = 'const {rootNode, rootNodeWithOffset, edit} = Tree.prototype;';
  const newPreserve = `if (!Tree.prototype._nativeRootNode) {
  Tree.prototype._nativeRootNode = Tree.prototype.rootNode;
}
if (!Tree.prototype._nativeRootNodeWithOffset) {
  Tree.prototype._nativeRootNodeWithOffset = Tree.prototype.rootNodeWithOffset;
}
if (!Tree.prototype._nativeEdit) {
  Tree.prototype._nativeEdit = Tree.prototype.edit;
}

const nativeRootNode = Tree.prototype._nativeRootNode;
const nativeRootNodeWithOffset = Tree.prototype._nativeRootNodeWithOffset;
const nativeEdit = Tree.prototype._nativeEdit;`;

  if (content.includes(oldDestructure)) {
    content = content.replace(oldDestructure, newPreserve);
    modified = true;
  }

  // 2. Patch restrictive this instanceof Tree check on rootNode getter
  if (content.includes('if (this instanceof Tree && rootNode)')) {
    content = content.replace(
      'if (this instanceof Tree && rootNode)',
      'if (this && this !== Tree.prototype && nativeRootNode)'
    );
    modified = true;
  } else if (content.includes('return unmarshalNode(rootNode.call(this), this);')) {
    content = content.replace(
      'return unmarshalNode(rootNode.call(this), this);',
      'return unmarshalNode(nativeRootNode.call(this), this);'
    );
    modified = true;
  }

  // 3. Patch rootNodeWithOffset to use nativeRootNodeWithOffset
  if (content.includes('return unmarshalNode(rootNodeWithOffset.call(this')) {
    content = content.replace(
      'return unmarshalNode(rootNodeWithOffset.call(this',
      'return unmarshalNode(nativeRootNodeWithOffset.call(this'
    );
    modified = true;
  }

  // 4. Patch unmarshalNode NodeClass constructor fallback
  if (content.includes(': tree.language.nodeSubclasses[nodeTypeId];')) {
    content = content.replace(
      ': tree.language.nodeSubclasses[nodeTypeId];',
      ': (tree.language && tree.language.nodeSubclasses && typeof tree.language.nodeSubclasses[nodeTypeId] === "function" ? tree.language.nodeSubclasses[nodeTypeId] : SyntaxNode);'
    );
    modified = true;
  }

  if (modified) {
    fs.writeFileSync(treeSitterIndexPath, content, 'utf8');
    console.log('[MCP-SHIELD] Patched tree-sitter for multi-realm and CI worker stability.');
  }
}
