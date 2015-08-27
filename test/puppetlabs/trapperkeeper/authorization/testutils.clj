(ns puppetlabs.trapperkeeper.authorization.testutils
  (:require [puppetlabs.ssl-utils.core :as ssl])
  (:import (org.joda.time DateTime Period)))

(defn request
  "Builds a ring request"
  [path method certificate ip]
  {:uri path :request-method method :remote-addr ip :ssl-client-cert certificate})

;; Extracted from ssl-utils test

(defn- generate-not-before-date []
  (-> (DateTime/now)
      (.minus (Period/days 1))
      (.toDate)))

(defn- generate-not-after-date []
  (-> (DateTime/now)
      (.plus (Period/years 5))
      (.toDate)))

(defn create-certificate
  [cn]
  (let [subject (ssl/cn cn)
        key-pair (ssl/generate-key-pair 512)
        subj-pub (ssl/get-public-key key-pair)
        issuer (ssl/cn "my ca")
        issuer-key-pair (ssl/generate-key-pair 512)
        issuer-priv (ssl/get-private-key issuer-key-pair)
        not-before (generate-not-before-date)
        not-after (generate-not-after-date)
        serial 42]
    (ssl/sign-certificate issuer issuer-priv serial not-before not-after subject subj-pub)))

(def test-domain-cert (create-certificate "test.domain.org"))
(def test-other-cert (create-certificate "www.other.org"))
(def test-denied-cert (create-certificate "bad.guy.com"))
