(ns puppetlabs.trapperkeeper.authorization.acl-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [clojure.string :as str]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(deftest test-compare-entry
  (testing "deny before allow"
    (let [allow-host (acl/new-domain :allow "www.google.com")
          deny-host (acl/new-domain :deny "www.google.com")]
      (is (= -1 (acl/ace-compare deny-host allow-host)))
      (is (= 1 (acl/ace-compare allow-host deny-host)))))
  (testing "existing allow before new allow"
    (let [allow-host-1 (acl/new-domain :allow "www.first.com")
          allow-host-2 (acl/new-domain :allow "www.second.com")]
      (is (= 1 (acl/ace-compare allow-host-1 allow-host-2)))
      (is (= 1 (acl/ace-compare allow-host-2 allow-host-1)))))
  (testing "existing deny before new deny"
    (let [deny-host-1 (acl/new-domain :deny "www.first.com")
          deny-host-2 (acl/new-domain :deny "www.second.com")]
      (is (= 1 (acl/ace-compare deny-host-1 deny-host-2)))
      (is (= 1 (acl/ace-compare deny-host-2 deny-host-1))))))

(def valid-names
  ["spirit.mars.nasa.gov"
   "ratchet.2ndsiteinc.com"
   "a.c.ru"
   ])

(deftest test-valid-names-ace
  (doseq [name valid-names]
    (let [acl (acl/new-domain :allow name)]
      (testing (str name " match input name")
        (is (acl/match? acl name))))))

(def valid-names-wildcard
  [ "abc.12seps.edu.phisher.biz" "www.google.com" "slashdot.org"])

(deftest test-valid-names-ace-wildcard
  (doseq [name valid-names-wildcard]
    (let [name-split (str/split name #"\.")]
      (doseq [i (range 1 (count name-split))]
        (let [host (str/join "." (concat ["*"] (reverse (take i (reverse name-split)))))
             acl (acl/new-domain :allow host)]
          (testing (str host " match input name")
            (is (acl/match? acl name)))
          (testing (str host " doesn't match www.testsite.gov")
            (is (not (acl/match? acl "www.testsite.gov"))))
          (testing (str host " doesn't match hosts that differ in the first non-wildcard segment")
            (let [other-split (str/split name #"\.")
                  pos (- (count other-split) i)
                  other (str/join "." (assoc other-split pos (str "test" (nth other-split pos))))]
              (is (not (acl/match? acl other))))))))))

(deftest test-fqdn
  (testing "match a similar PQDN"
    (is (not (acl/match? (acl/new-domain :allow "spirit.mars.nasa.gov.") "spirit.mars.nasa.gov")))))

(deftest test-regex
  (let [acl (acl/new-domain :allow "/^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/")]
    (doseq [host ["host5.other-domain.com" "test-host12.other-domain.net" "foo.some-domain.com"]]
      (testing (str host "match regex")
        (is (acl/match? acl host))))
    (doseq [host ["'host0.some-other-domain.com" ""]]
      (testing (str host " doesn't match regex")
        (is (not (acl/match? acl host)))))))

(deftest test-backreference-interpolation
  (testing "injecting backreference values"
    (let [acl (acl/new-domain :allow "$1.$2.domain.com")]
      (is (= (:pattern (acl/interpolate-backreference acl ["a" "b"])) ["com" "domain" "b" "a"])))))

(deftest test-empty-acl
  (testing "it is empty"
    (is (= 0 (count acl/empty-acl)))))

(deftest test-acl-creation
  (testing "not empty when allowing a domain"
    (is (not= 0 (count (acl/allow "www.google.com")))))
  (testing "not empty when denying a domain"
    (is (not= 0 (count (acl/deny "www.google.com"))))))

(deftest test-acl-ordering
  (testing "deny ACEs ordered before allow ACEs"
    (let [expected-acl [(acl/new-domain :deny "*.domain.com")
                        (acl/new-domain :deny "my.domain.com")
                        (acl/new-domain :allow "*.domain.com")
                        (acl/new-domain :allow "my.domain.com")]]
      (testing "when allow ACEs added first"
        (is (= expected-acl (-> (acl/allow "*.domain.com")
                                (acl/allow "my.domain.com")
                                (acl/deny "*.domain.com")
                                (acl/deny "my.domain.com")
                                vec))))
      (testing "when deny ACEs added first"
        (is (= expected-acl (-> (acl/deny "*.domain.com")
                                (acl/deny "my.domain.com")
                                (acl/allow "*.domain.com")
                                (acl/allow "my.domain.com")
                                vec))))
      (testing "when ACEs added in mixed order"
        (is (= expected-acl (-> (acl/allow "*.domain.com")
                                (acl/deny "*.domain.com")
                                (acl/deny "my.domain.com")
                                (acl/allow "my.domain.com")
                                vec)))))))

(deftest test-acl-matching
  (let [acl (-> (acl/allow "*.domain.com")
                (acl/deny "*.test.org"))]
    (testing "allowing by name"
      (is (acl/allowed? acl "test.domain.com")))
    (testing "denying by name"
      (is (not (acl/allowed? acl "www.test.org"))))
    (testing "no match is deny"
      (is (not (acl/allowed? acl "www.google.com"))))))

(deftest test-global-allow
  (let [acl (acl/allow "*")]
    (testing "should allow anything"
      (is (acl/allowed? acl "anything")))))

(deftest test-acl-matching-with-captures
  (testing "matching backreference of simple name"
    (let [acl (acl/allow "$1.google.com")]
      (is (acl/allowed? acl "www.google.com" ["www"]))))
  (testing "matching backreference of opaque name"
    (let [acl (acl/allow "$1")]
      (is (acl/allowed? acl "c216f41a-f902-4bfb-a222-850dd957bebb" ["c216f41a-f902-4bfb-a222-850dd957bebb"]))))
  (testing "matching backreference of name"
    (let [acl (acl/allow "$1")]
      (is (acl/allowed? acl "admin.mgmt.nym1" ["admin.mgmt.nym1"])))))
