(ns puppetlabs.trapperkeeper.authorization.acl-test
  (:require [clojure.test :refer :all]
            [puppetlabs.trapperkeeper.authorization.acl :as acl]
            [puppetlabs.trapperkeeper.authorization.report :as report]
            [clojure.string :as str]
            [puppetlabs.trapperkeeper.authorization.testutils :refer [is-allowed is-not-allowed request]]
            [schema.test :as schema-test]))

(use-fixtures :once schema-test/validate-schemas)

(deftest test-compare-entry
  (let [ip (acl/new-ip :allow "127.0.0.1")
        host (acl/new-domain :allow "www.google.com")
        opaque (acl/new-domain :allow "opaque")
        inexact (acl/new-domain :allow "*.inexact.com")]
    (testing "ip?"
      (is (acl/ip? ip))
      (is (not (acl/ip? host))))
    (testing "exact?"
      (is (acl/exact? host))
      (is (not (acl/exact? inexact))))
    (testing "ip before host"
      (is (= -1 (acl/ace-compare ip host))))
    (testing "ip before opaque"
      (is (= -1 (acl/ace-compare ip opaque))))))

(deftest test-ip-ace
  (let [ips ["100.101.99.98" "100.100.100.100" "1.2.3.4" "11.22.33.44"]]
    (doseq [ip ips]
      (let [acl (acl/new-ip :allow ip)]
          (testing (str ip " match input ip")
                   (is (acl/match? acl "test.domain.com" ip)))
          (testing (str ip " doesn't match other ip")
            (is (not (acl/match? acl "test.domain.com" "202.124.67.29")))))
      (doseq [i (range 1 4)]
        (let [ip-pattern (str (str/join "." (take i (str/split ip #"\."))) ".*")
              acl (acl/new-ip :allow ip-pattern)]
          (testing (str ip-pattern " match ip")
            (is (acl/match? acl "test.domain.com" ip)))
          (testing (str ip-pattern " doesn't match other ip")
            (is (not (acl/match? acl "test.domain.com" "202.124.67.29")))))))))


(def valid-ips
  [
   "1.2.3.4"
   "2001:0000:1234:0000:0000:C1C0:ABCD:0876"
   "3ffe:0b00:0000:0000:0001:0000:0000:000a"
   "FF02:0000:0000:0000:0000:0000:0000:0001"
   "0000:0000:0000:0000:0000:0000:0000:0001"
   "0000:0000:0000:0000:0000:0000:0000:0000"
   "::ffff:192.168.1.26"
   "2::10"
   "ff02::1"
   "fe80::"
   "2002::"
   "2001:db8::"
   "2001:0db8:1234::"
   "::ffff:0:0"
   "::1"
   "::ffff:192.168.1.1"
   "1:2:3:4:5:6:7:8"
   "1:2:3:4:5:6::8"
   "1:2:3:4:5::8"
   "1:2:3:4::8"
   "1:2:3::8"
   "1:2::8"
   "1::8"
   "1::2:3:4:5:6:7"
   "1::2:3:4:5:6"
   "1::2:3:4:5"
   "1::2:3:4"
   "1::2:3"
   "1::8"
   "::2:3:4:5:6:7"
   "::2:3:4:5:6"
   "::2:3:4:5"
   "::2:3:4"
   "::2:3"
   "::8"
   "1:2:3:4:5:6::"
   "1:2:3:4:5::"
   "1:2:3:4::"
   "1:2:3::"
   "1:2::"
   "1::"
   "1:2:3:4:5::7:8"
   "1:2:3:4::7:8"
   "1:2:3::7:8"
   "1:2::7:8"
   "1::7:8"
   "1:2:3:4:5:6:1.2.3.4"
   "1:2:3:4:5::1.2.3.4"
   "1:2:3:4::1.2.3.4"
   "1:2:3::1.2.3.4"
   "1:2::1.2.3.4"
   "1::1.2.3.4"
   "1:2:3:4::5:1.2.3.4"
   "1:2:3::5:1.2.3.4"
   "1:2::5:1.2.3.4"
   "1::5:1.2.3.4"
   "1::5:11.22.33.44"
   "fe80::217:f2ff:254.7.237.98"
   "fe80::217:f2ff:fe07:ed62"
   "2001:DB8:0:0:8:800:200C:417A" ;unicast, full
   "FF01:0:0:0:0:0:0:101" ;multicast, full
   "0:0:0:0:0:0:0:1" ;loopback, full
   "0:0:0:0:0:0:0:0" ;unspecified, full
   "2001:DB8::8:800:200C:417A" ;unicast, compressed
   "FF01::101" ;multicast, compressed
   "::1" ;loopback, compressed, non-routable
   "::" ;unspecified, compressed, non-routable
   "0:0:0:0:0:0:13.1.68.3" ;IPv4-compatible IPv6 address, full, deprecated
   "0:0:0:0:0:FFFF:129.144.52.38" ;IPv4-mapped IPv6 address, full
   "::13.1.68.3" ;IPv4-compatible IPv6 address, compressed, deprecated
   "::FFFF:129.144.52.38" ;IPv4-mapped IPv6 address, compressed
   "2001:0DB8:0000:CD30:0000:0000:0000:0000/60" ;full, with prefix
   "2001:0DB8::CD30:0:0:0:0/60" ;compressed, with prefix
   "2001:0DB8:0:CD30::/60" ;compressed, with prefix #2
   "::/128" ;compressed, unspecified address type, non-routable
   "::1/128" ;compressed, loopback address type, non-routable
   "FF00::/8" ;compressed, multicast address type
   "FE80::/10" ;compressed, link-local unicast, non-routable
   "FEC0::/10" ;compressed, site-local unicast, deprecated
   "127.0.0.1" ;standard IPv4, loopback, non-routable
   "0.0.0.0" ;standard IPv4, unspecified, non-routable
   "255.255.255.255" ;standard IPv4
   "fe80:0000:0000:0000:0204:61ff:fe9d:f156"
   "fe80:0:0:0:204:61ff:fe9d:f156"
   "fe80::204:61ff:fe9d:f156"
   "fe80:0:0:0:204:61ff:254.157.241.86"
   "fe80::204:61ff:254.157.241.86"
   "::1"
   "fe80::"
   "fe80::1"
   ])

(deftest test-valid-ip-ace
  (doseq [ip valid-ips]
    (let [acl (acl/new-ip :allow ip)]
      (testing (str ip " match input ip")
        (is (acl/match? acl "test.domain.com" ip)))
      (testing (str ip " doesn't match other ip")
        (is (not (acl/match? acl "test.domain.com" "202.124.67.29")))))))

(def valid-names
  ["spirit.mars.nasa.gov"
   "ratchet.2ndsiteinc.com"
   "a.c.ru"
   ])

(deftest test-valid-names-ace
  (doseq [name valid-names]
    (let [acl (acl/new-domain :allow name)]
      (testing (str name " match input name")
        (is (acl/match? acl name "127.0.0.1"))))))

(def valid-names-wildcard
  [ "abc.12seps.edu.phisher.biz" "www.google.com" "slashdot.org"])

(deftest test-valid-names-ace-wildcard
  (doseq [name valid-names-wildcard]
    (let [name-split (str/split name #"\.")]
      (doseq [i (range 1 (count name-split))]
        (let [host (str/join "." (concat ["*"] (reverse (take i (reverse name-split)))))
             acl (acl/new-domain :allow host)]
          (testing (str host " match input name")
            (is (acl/match? acl name "127.0.0.1")))
          (testing (str host " doesn't match www.testsite.gov")
            (is (not (acl/match? acl "www.testsite.gov" "127.0.0.1"))))
          (testing (str host " doesn't match hosts that differ in the first non-wildcard segment")
            (let [other-split (str/split name #"\.")
                  pos (- (count other-split) i)
                  other (str/join "." (assoc other-split pos (str "test" (nth other-split pos))))]
              (is (not (acl/match? acl other "127.0.0.1"))))))))))

(deftest test-fqdn
  (testing "match a similar PQDN"
    (is (not (acl/match? (acl/new-domain :allow "spirit.mars.nasa.gov.") "spirit.mars.nasa.gov" "127.0.0.1")))))

(deftest test-regex
  (let [acl (acl/new-domain :allow "/^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/")]
    (doseq [host ["host5.other-domain.com" "test-host12.other-domain.net" "foo.some-domain.com"]]
      (testing (str host "match regex")
        (is (acl/match? acl host "127.0.0.1"))))
    (doseq [host ["'host0.some-other-domain.com" ""]]
      (testing (str host " doesn't match regex")
        (is (not (acl/match? acl host "127.0.0.1")))))))

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
    (is (not= 0 (count (acl/deny "www.google.com")))))
  (testing "not empty when allowing an ip"
    (is (not= 0 (count (acl/allow-ip "192.168.0.0/24")))))
  (testing "not empty when denying an ip"
    (is (not= 0 (count (acl/deny-ip "192.168.0.0/24"))))))

(deftest test-acl-ordering
  (testing "allow before deny"
    (is (= :allow) (:auth-type (first (acl/deny (acl/allow "www.google.com") "www.domain.com")))))
  (testing "ip before name"
    (is (= :ip) (:type (first (acl/allow-ip (acl/allow "www.google.com") "192.168.0.0/24"))))))

(deftest test-acl-matching
  (let [acl (-> (acl/allow "*.domain.com") (acl/allow-ip "192.168.0.0/24") (acl/deny "*.test.org") (acl/deny-ip "127.0.0.0/8"))]
    (testing "allowing by name"
      (is-allowed (acl/allowed? acl "test.domain.com" "10.1.1.23")))
    (testing "allowing by ip"
      (is-allowed (acl/allowed? acl "www.google.com" "192.168.0.24")))
    (testing "denying by name"
      (is-not-allowed (acl/allowed? acl "www.test.org" "10.1.1.23")))
    (testing "denying by ip"
      (is-not-allowed (acl/allowed? acl "www.google.com" "127.12.34.56")))
    (testing "no match is deny"
      (is-not-allowed (acl/allowed? acl "www.google.com" "212.23.45.67")))))

(deftest test-global-allow
  (let [acl (acl/allow "*")]
    (testing "should allow anything"
      (is-allowed (acl/allowed? acl "anything" "127.0.0.1")))))

(deftest test-acl-matching-with-captures
  (testing "matching backreference of simple name"
    (let [acl (acl/allow "$1.google.com")]
      (is-allowed (acl/allowed? acl "www.google.com" "127.0.0.1" ["www"]))))
  (testing "matching backreference of opaque name"
    (let [acl (acl/allow "$1")]
      (is-allowed (acl/allowed? acl "c216f41a-f902-4bfb-a222-850dd957bebb" "127.0.0.1" ["c216f41a-f902-4bfb-a222-850dd957bebb"]))))
  (testing "matching backreference of name"
    (let [acl (acl/allow "$1")]
      (is-allowed (acl/allowed? acl "admin.mgmt.nym1" "127.0.0.1" ["admin.mgmt.nym1"])))))

(deftest test-single-entry->string
  (testing "human-readable allow entry form"
    (is (= (acl/acl->string (acl/allow "www.google.com")) ["allow www.google.com"]))
    (is (= (acl/acl->string (acl/allow "*.google.com")) ["allow *.google.com"]))
    (is (= (acl/acl->string (acl/allow "$1.google.com")) ["allow $1.google.com"]))
    (is (= (acl/acl->string (acl/allow "*")) ["allow *"]))
    (is (= (acl/acl->string (acl/allow "opaque")) ["allow opaque"]))
    (is (= (acl/acl->string (acl/allow "/^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/")) ["allow /^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/"]))
    (is (= (acl/acl->string (acl/allow-ip "192.168.5.25")) ["allow 192.168.5.25"]))
    (is (= (acl/acl->string (acl/allow-ip "192.168.5.*")) ["allow 192.168.5.0/24"]))
    (is (= (acl/acl->string (acl/allow-ip "192.168.5.0/24")) ["allow 192.168.5.0/24"])))
  (testing "human-readable deny entry form"
    (is (= (acl/acl->string (acl/deny "www.google.com")) ["deny www.google.com"]))
    (is (= (acl/acl->string (acl/deny "*.google.com")) ["deny *.google.com"]))
    (is (= (acl/acl->string (acl/deny "$1.google.com")) ["deny $1.google.com"]))
    (is (= (acl/acl->string (acl/deny "*")) ["deny /^*$/"]))
    (is (= (acl/acl->string (acl/deny "opaque")) ["deny opaque"]))
    (is (= (acl/acl->string (acl/deny "/^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/")) ["deny /^(test-)?host[0-9]+\\.other-domain\\.(com|org|net)$|some-domain\\.com/"]))
    (is (= (acl/acl->string (acl/deny-ip "192.168.5.25")) ["deny 192.168.5.25"]))
    (is (= (acl/acl->string (acl/deny-ip "192.168.5.*")) ["deny 192.168.5.0/24"]))
    (is (= (acl/acl->string (acl/deny-ip "192.168.5.0/24")) ["deny 192.168.5.0/24"]))))

(deftest test-acl->string
  (testing "a set of allow and deny"
    (let [acl (-> (acl/allow "*.domain.com") (acl/allow-ip "192.168.0.0/24") (acl/deny "*.test.org") (acl/deny-ip "127.0.0.0/8"))]
      (is (= (acl/acl->string acl) ["allow 192.168.0.0/24" "deny 127.0.0.0/8" "deny *.test.org" "allow *.domain.com"])))))

(deftest test-acl-allowed-report
  (testing "match report"
    (let [acl (-> (acl/allow "*.domain.com") (acl/allow-ip "192.168.0.0/24") (acl/deny "*.test.org") (acl/deny-ip "127.0.0.0/8"))]
      (is (= 4 (count (:report (acl/allowed? acl "www.domain.org" "172.16.10.4")))))
      (is (=  (count (:report (acl/allowed? acl "www.domain.org" "172.16.10.4"))))))))