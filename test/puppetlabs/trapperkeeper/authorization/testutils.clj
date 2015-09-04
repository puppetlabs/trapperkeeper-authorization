(ns puppetlabs.trapperkeeper.authorization.testutils
  (:require [puppetlabs.ssl-utils.simple :as ssl]
            [ring.mock.request :as mock]))

(defn request
  "Build a ring request for testing"
  ([path method]
   (request path method "127.0.0.1"))
  ([path method ip]
   (assoc (mock/request method path) :remote-addr ip))
  ([path method ip certificate]
   (assoc (request path method ip) :ssl-client-cert certificate)))

(defn create-certificate
  [cn]
  (let [cacert (ssl/gen-self-signed-cert "my ca" 41 {:keylength 512})]
    (:cert (ssl/gen-cert cn cacert 42 {:keylength 512}))))

(def test-domain-cert (create-certificate "test.domain.org"))
(def test-other-cert (create-certificate "www.other.org"))
(def test-denied-cert (create-certificate "bad.guy.com"))
