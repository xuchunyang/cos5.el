;;; cos5-tests.el --- Tests                          -*- lexical-binding: t; -*-

;; Copyright (C) 2020  Xu Chunyang

;; Author: Xu Chunyang <xuchunyang56@gmail.com>

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

;; Tests for cos5.el

;;; Code:

(require 'cos5)
(require 'ert)

(ert-deftest cos5--sign ()
  (should (string= (cos5--sign "1606464952;1606468552"
                               "secretid"
                               "secretkey"
                               "GET"
                               "/"
                               '(("max-keys" . "20")
                                 ("prefix" . "abc"))
                               '(("Content-Type" . "image/jpeg")
                                 ("host" . "test-1250000000.cos.ap-beijing.mycloud.com")))
                   "q-sign-algorithm=sha1&q-ak=secretid&q-sign-time=1606464952;1606468552&q-key-time=1606464952;1606468552&q-header-list=content-type;host&q-url-param-list=max-keys;prefix&q-signature=775656599f1674896f8cba8818b5300d19e021be")))

(provide 'cos5-tests)
;;; cos5-tests.el ends here
