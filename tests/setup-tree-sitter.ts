import Parser from 'tree-sitter';
import Bash from 'tree-sitter-bash';

// Preserve Tree-sitter prototype descriptors across multi-realm (Jest) test environments in-memory
const TreeClass = (Parser as any).Tree;
if (TreeClass?.prototype) {
  if (!TreeClass.prototype._savedRootNodeDesc) {
    TreeClass.prototype._savedRootNodeDesc = Object.getOwnPropertyDescriptor(TreeClass.prototype, 'rootNode');
    TreeClass.prototype._savedRootNodeWithOffsetDesc = Object.getOwnPropertyDescriptor(TreeClass.prototype, 'rootNodeWithOffset');
    TreeClass.prototype._savedEditDesc = Object.getOwnPropertyDescriptor(TreeClass.prototype, 'edit');
  } else {
    if (TreeClass.prototype._savedRootNodeDesc) {
      Object.defineProperty(TreeClass.prototype, 'rootNode', TreeClass.prototype._savedRootNodeDesc);
    }
    if (TreeClass.prototype._savedRootNodeWithOffsetDesc) {
      Object.defineProperty(TreeClass.prototype, 'rootNodeWithOffset', TreeClass.prototype._savedRootNodeWithOffsetDesc);
    }
    if (TreeClass.prototype._savedEditDesc) {
      Object.defineProperty(TreeClass.prototype, 'edit', TreeClass.prototype._savedEditDesc);
    }
  }
}

try {
  delete (Bash as any).nodeSubclasses;
} catch {}
