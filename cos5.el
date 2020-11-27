;;; cos5.el --- Tencent Cloud COS SDK               -*- lexical-binding: t; -*-

;; Copyright (C) 2020  Xu Chunyang

;; Author: Xu Chunyang <xuchunyang56@gmail.com>
;; Homepage: https://github.com/xuchunyang/cos5.el
;; Created: 2020-11-27
;; Package-Requires: ((emacs "26.1"))
;; Version: 0

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; 腾讯云对象存储 SDK
;;
;; XML API https://cloud.tencent.com/document/product/436/7751

;;; Code:

(require 'cl-lib)                       ; `cl-sort'

;;;; 请求签名 https://cloud.tencent.com/document/product/436/7778

(defun cos5--unibyte-string-to-hex (s)
  "Convert unibyte string S to hex."
  (mapconcat (lambda (char) (format "%02x" char)) s ""))

(defun cos5--hmac-sha1 (key value)
  "Compute HMAC-SHA1(KEY, VALUE) and return the hex form."
  (cos5--unibyte-string-to-hex (gnutls-hash-mac 'SHA1 key value)))

(defun cos5--KeyTime (duration)
  "Return a keytime, the key is valid for next DURATION seconds."
  (let ((StartTimestamp (format-time-string "%s"))
        (EndTimestamp (format-time-string "%s" (time-add nil duration))))
    (format "%s;%s" StartTimestamp EndTimestamp)))

(defun cos5--sign (KeyTime
                   SecretId
                   SecretKey
                   HttpMethod
                   HttpURI
                   HttpParameters
                   HttpHeaders)
  "Sign the request.
According to
\(KEYTIME SECRETID SECRETKEY HTTPMETHOD HTTPURI HTTPPARAMETERS HTTPHEADERS).

HTTPPARAMETERS and HTTPHEADERS are alist.

See URL `https://cloud.tencent.com/document/product/436/7778'."
  (let* ((SignKey (cos5--hmac-sha1 SecretKey KeyTime))
         (HttpParameters (cl-sort
                          (mapcar
                           (pcase-lambda (`(,key . ,value))
                             (cons (downcase key)
                                   (url-hexify-string value)))
                           HttpParameters)
                          #'string<
                          :key #'car))
         (UrlParamList (mapconcat #'car HttpParameters ";"))
         (HttpParameters (mapconcat
                          (pcase-lambda (`(,key . ,value))
                            (format "%s=%s" key value))
                          HttpParameters
                          "&"))
         (HttpHeaders (cl-sort
                       (mapcar
                        (pcase-lambda (`(,key . ,value))
                          (cons (url-hexify-string (downcase key))
                                (url-hexify-string value)))
                        HttpHeaders)
                       #'string<
                       :key #'car))
         (HeaderList (mapconcat #'car HttpHeaders ";"))
         (HttpHeaders (mapconcat
                       (pcase-lambda (`(,key . ,value))
                         (format "%s=%s" key value))
                       HttpHeaders
                       "&"))
         (HttpString (format "%s\n%s\n%s\n%s\n"
                             (downcase HttpMethod)
                             HttpURI
                             HttpParameters
                             HttpHeaders))
         (StringToSign (format "sha1\n%s\n%s\n"
                               KeyTime
                               (sha1 HttpString)))
         (Signature (cos5--hmac-sha1 SignKey StringToSign)))
    (mapconcat
     (pcase-lambda (`(,key . ,value))
       (format "%s=%s" key value))
     `((q-sign-algorithm . "sha1")
       (q-ak . ,SecretId)
       (q-sign-time . ,KeyTime)
       (q-key-time . ,KeyTime)
       (q-header-list . ,HeaderList)
       (q-url-param-list . ,UrlParamList)
       (q-signature . ,Signature))
     "&")))

(provide 'cos5)
;;; cos5.el ends here
