/**
 * Custom ESLint rule: require-motion-policy
 *
 * Ensures that JSX elements from `motion.*` (framer-motion) are only used
 * when the calling function/component has checked `policy.allowFramer`.
 *
 * This prevents animations from running when the user has requested
 * reduced motion or animations are disabled.
 *
 * Good:
 *   initial={policy.allowFramer ? { opacity: 0 } : false}
 *
 * Bad:
 *   initial={{ opacity: 0 }}
 */
export default {
  meta: {
    type: 'suggestion',
    docs: {
      description: 'Require policy.allowFramer check before using motion.* components',
      category: 'Accessibility',
    },
    messages: {
      missingPolicyCheck:
        'motion.{{name}} used without checking policy.allowFramer. Wrap in a conditional or use policy.allowFramer ? ... : false.',
    },
  },
  create(context) {
    const sourceCode = context.getSourceCode();
    let hasAllowFramerCheck = false;
    const scopes = new Set();

    return {
      'FunctionDeclaration, FunctionExpression, ArrowFunctionExpression'(node) {
        const scope = node;
        scopes.add(scope);
        const body = node.body?.body || (node.body?.type === 'BlockStatement' ? node.body.body : []);
        // Check if this function body contains a reference to policy.allowFramer
        if (node.body && node.body.type !== 'BlockStatement') return;
        const text = sourceCode.getText(node);
        if (text.includes('policy.allowFramer')) {
          scopes.delete(scope);
        }
      },
      JSXOpeningElement(node) {
        if (
          node.name.type === 'JSXMemberExpression' &&
          node.name.object.type === 'JSXIdentifier' &&
          node.name.object.name === 'motion'
        ) {
          let scope = context.getScope?.();
          // Walk up scope chain to find if allowFramer was checked
          let found = false;
          while (scope) {
            const block = scope.block;
            if (block && scopes.has(block)) {
              found = true;
              break;
            }
            if (block && sourceCode.getText(block).includes('policy.allowFramer')) {
              found = true;
              break;
            }
            scope = scope.upper;
          }
          if (!found) {
            context.report({
              node,
              messageId: 'missingPolicyCheck',
              data: { name: node.name.property?.name || 'element' },
            });
          }
        }
      },
      ':function'(node) {
        scopes.delete(node);
      },
    };
  },
};
