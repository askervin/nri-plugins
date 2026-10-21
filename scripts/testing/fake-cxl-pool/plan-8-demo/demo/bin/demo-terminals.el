;;; demo-terminals.el --- Six-terminal CXL demo layout -*- lexical-binding: t; -*-

;;; Commentary:
;; Install multi-vterm and its vterm dependency, then launch from demo/:
;;   emacs --geometry 106x40 -l bin/demo-terminals.el -f cxl-demo-terminals
;; In an existing Emacs, M-x load-file this file, then M-x cxl-demo-terminals.
;; This replaces the selected frame's layout, without killing its buffers.
;; Shells start in demo/; no setup, views or presenter steps run automatically.

;;; Code:

(require 'cl-lib)

(declare-function multi-vterm "multi-vterm")
(defvar vterm-min-window-width)
(defvar vterm-buffer-name-string)

(defconst cxl-demo--directory
  (file-name-directory
   (directory-file-name
    (file-name-directory (or load-file-name buffer-file-name))))
  "Directory containing the demo.")

(defconst cxl-demo--captions
  '("PRESENTER" "PODS & LEASES" "SCHEDULER" "NODES" "TRACE" "MEMORY / POOL")
  "Terminal captions in row-major order.")

(defun cxl-demo-terminals ()
  "Show six multi-vterm shells in the CXL demo's two-column, three-row layout."
  (interactive)
  (unless (require 'multi-vterm nil t)
    (user-error "Install multi-vterm and its vterm dependency first"))
  (let ((names (cl-loop for caption in cxl-demo--captions
                        for number from 1
                        collect (format "*T%d %s*" number caption)))
        (configuration (current-window-configuration)))
    (dolist (name names)
      (when-let ((buffer (get-buffer name)))
        (unless (with-current-buffer buffer (derived-mode-p 'vterm-mode))
          (user-error "Buffer %s already exists and is not a vterm" name))))
    (condition-case err
        (progn
          (delete-other-windows)
          (let* ((top (selected-window))
                 (middle (split-window top (/ (window-total-height top) 3)
                                       'below))
                 (bottom (split-window middle nil 'below))
                 (windows
                  (cl-loop for left in (list top middle bottom)
                           append (list left (split-window left nil 'right)))))
            (balance-windows)
            (unless (cl-every
                     (lambda (window)
                       (and (>= (window-body-width window) 50)
                            (>= (window-body-height window) 10)))
                     windows)
              (user-error "Enlarge the frame: each demo pane needs at least 50x10"))
            (cl-mapc
             (lambda (window name)
               (select-window window)
               (if-let ((buffer (get-buffer name)))
                   (switch-to-buffer buffer)
                 (let ((default-directory cxl-demo--directory)
                       (vterm-min-window-width 50)
                       (vterm-buffer-name-string nil))
                   (multi-vterm))
                 (rename-buffer name))
               (setq-local vterm-min-window-width 50
                           vterm-buffer-name-string nil))
             windows names)
            (select-window top)))
      (error
       (set-window-configuration configuration)
       (signal (car err) (cdr err))))))

(provide 'demo-terminals)
;;; demo-terminals.el ends here
