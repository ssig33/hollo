((nil . ((eglot-server-programs . (((html-mode
                                     css-mode css-ts-mode
                                     (js-mode :language-id "javascript")
                                     (js-ts-mode :language-id "javascript")
                                     (typescript-mode :language-id "typescript")
                                     (typescript-ts-mode :language-id "typescript")
                                     (tsx-ts-mode :language-id "typescriptreact")
                                     js-json-mode json-mode json-ts-mode jsonc-mode)
                                    "biome" "lsp-proxy")))
         (eval . (add-hook 'before-save-hook
                           (lambda ()
                             (eglot-format-buffer)
                             (when (member major-mode '(js-mode
                                                        js-ts-mode
                                                        typescript-mode
                                                        typescript-ts-mode
                                                        tsx-ts-mode))
                               (eglot-code-actions (point-min) (point-max)
                                                   "source.organizeImports.biome" t))))))))
