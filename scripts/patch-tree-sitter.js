const fs = require('fs');
const path = require('path');

const treeSitterIndexPath = path.resolve(__dirname, '../node_modules/tree-sitter/index.js');

if (fs.existsSync(treeSitterIndexPath)) {
  let content = fs.readFileSync(treeSitterIndexPath, 'utf8');
  let modified = false;

  // 1. Preserve native Tree.prototype methods across multiple module evaluations in Jest
  const oldTreeDestructure = 'const {rootNode, rootNodeWithOffset, edit} = Tree.prototype;';
  const newTreePreserve = `if (!Tree.prototype._nativeRootNode) {
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

  if (content.includes(oldTreeDestructure)) {
    content = content.replace(oldTreeDestructure, newTreePreserve);
    modified = true;
  }

  // 2. Patch restrictive this instanceof Tree checks on rootNode and edit
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

  if (content.includes('if (this instanceof Tree && edit)')) {
    content = content.replace(
      'if (this instanceof Tree && edit) {\n    edit.call(',
      'if (this && nativeEdit) {\n    nativeEdit.call('
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

  // 4. Preserve native Parser.prototype methods
  const oldParserDestructure = 'const {parse, setLanguage} = Parser.prototype;';
  const newParserPreserve = `if (!Parser.prototype._nativeParse) {
  Parser.prototype._nativeParse = Parser.prototype.parse;
}
if (!Parser.prototype._nativeSetLanguage) {
  Parser.prototype._nativeSetLanguage = Parser.prototype.setLanguage;
}

const nativeParse = Parser.prototype._nativeParse;
const nativeSetLanguage = Parser.prototype._nativeSetLanguage;`;

  if (content.includes(oldParserDestructure)) {
    content = content.replace(oldParserDestructure, newParserPreserve);
    modified = true;
  }

  if (content.includes('if (this instanceof Parser && setLanguage)')) {
    content = content.replace(
      'if (this instanceof Parser && setLanguage) {\n    setLanguage.call(this, language);',
      'if (this && nativeSetLanguage) {\n    nativeSetLanguage.call(this, language);'
    );
    modified = true;
  }

  if (content.includes('const tree = this instanceof Parser && parse')) {
    content = content.replace(
      'const tree = this instanceof Parser && parse\n    ? parse.call(',
      'const tree = (this && nativeParse)\n    ? nativeParse.call('
    );
    modified = true;
  }

  // 5. Preserve native TreeCursor.prototype methods
  const oldCursorDestructure = 'const {startPosition, endPosition, currentNode} = TreeCursor.prototype;';
  const newCursorPreserve = `if (!TreeCursor.prototype._nativeStartPosition) {
  TreeCursor.prototype._nativeStartPosition = TreeCursor.prototype.startPosition;
}
if (!TreeCursor.prototype._nativeEndPosition) {
  TreeCursor.prototype._nativeEndPosition = TreeCursor.prototype.endPosition;
}
if (!TreeCursor.prototype._nativeCurrentNode) {
  TreeCursor.prototype._nativeCurrentNode = TreeCursor.prototype.currentNode;
}

const nativeStartPosition = TreeCursor.prototype._nativeStartPosition;
const nativeEndPosition = TreeCursor.prototype._nativeEndPosition;
const nativeCurrentNode = TreeCursor.prototype._nativeCurrentNode;`;

  if (content.includes(oldCursorDestructure)) {
    content = content.replace(oldCursorDestructure, newCursorPreserve);
    modified = true;
  }

  if (content.includes('if (this instanceof TreeCursor && currentNode)')) {
    content = content.replace(
      'if (this instanceof TreeCursor && currentNode)',
      'if (this && nativeCurrentNode)'
    );
    modified = true;
  }

  if (content.includes('if (this instanceof TreeCursor && startPosition)')) {
    content = content.replace(
      'if (this instanceof TreeCursor && startPosition) {\n        startPosition.call(this);',
      'if (this && nativeStartPosition) {\n        nativeStartPosition.call(this);'
    );
    modified = true;
  }

  if (content.includes('if (this instanceof TreeCursor && endPosition)')) {
    content = content.replace(
      'if (this instanceof TreeCursor && endPosition) {\n        endPosition.call(this);',
      'if (this && nativeEndPosition) {\n        nativeEndPosition.call(this);'
    );
    modified = true;
  }

  // 6. Patch marshalNode cross-realm instanceof check
  if (content.includes('if (!(node.tree instanceof Tree))')) {
    content = content.replace(
      'if (!(node.tree instanceof Tree))',
      'if (!node || !node.tree)'
    );
    modified = true;
  }

  // 7. Patch unmarshalNode NodeClass constructor fallback
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
