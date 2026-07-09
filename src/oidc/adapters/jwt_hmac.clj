(ns oidc.adapters.jwt-hmac
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [oidc.adapters.jwks :as jwks])
  (:import [java.nio.charset StandardCharsets]
           [java.util Base64]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defn- b64url-decode-string [s]
  (String. (.decode (Base64/getUrlDecoder) s) StandardCharsets/UTF_8))

(defn- b64url-decode-bytes [s]
  (.decode (Base64/getUrlDecoder) s))

(defn b64url-encode [bytes]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes))

(defn- hmac-sha256 [secret data]
  (let [mac (doto (Mac/getInstance "HmacSHA256")
              (.init (SecretKeySpec. (.getBytes secret StandardCharsets/UTF_8) "HmacSHA256")))]
    (.doFinal mac (.getBytes data StandardCharsets/UTF_8))))

(defn- constant-time= [a b]
  (java.security.MessageDigest/isEqual a b))

(defn- split-jwt [token]
  (let [parts (str/split token #"\.")]
    (when-not (= 3 (count parts))
      (throw (ex-info "invalid JWT compact serialization" {:parts (count parts)})))
    parts))

(defn- decode-part [decode-json part]
  (decode-json (b64url-decode-string part)))

(defn- now-seconds []
  (quot (System/currentTimeMillis) 1000))

(defn- claim-error [claims opts]
  (cond
    (and (:issuer opts) (not= (:issuer opts) (:iss claims))) :issuer
    (and (:audience opts)
         (let [aud (:aud claims)]
           (if (sequential? aud)
             (not (some #{(:audience opts)} aud))
             (not= (:audience opts) aud)))) :audience
    (and (:exp claims) (<= (:exp claims) (or (:now opts) (now-seconds)))) :expired
    (and (:nbf claims) (> (:nbf claims) (or (:now opts) (now-seconds)))) :not-yet-valid
    :else nil))

(defn hs256-verifier [secret opts]
  (let [decode-json (or (:decode-json opts) edn/read-string)]
    (reify jwks/IJwksVerifier
      (verify-jwt! [_ token-ref call-opts]
        (try
          (let [[header-seg claims-seg sig-seg] (split-jwt token-ref)
                signing-input (str header-seg "." claims-seg)
                header (decode-part decode-json header-seg)
                claims (decode-part decode-json claims-seg)
                expected (hmac-sha256 secret signing-input)
                actual (b64url-decode-bytes sig-seg)
                err (claim-error claims call-opts)]
            (cond
              (not= "HS256" (:alg header))
              {:error :unsupported-algorithm :alg (:alg header)}
              (not (constant-time= expected actual))
              {:error :invalid-signature}
              err
              (assoc claims :error err)
              :else
              (assoc claims :jwt-ref token-ref)))
          (catch Exception e
            {:error :invalid-jwt
             :message (ex-message e)}))))))

(defn sign-hs256 [secret header claims]
  (let [header-seg (b64url-encode (.getBytes (pr-str header) StandardCharsets/UTF_8))
        claims-seg (b64url-encode (.getBytes (pr-str claims) StandardCharsets/UTF_8))
        signing-input (str header-seg "." claims-seg)]
    (str signing-input "." (b64url-encode (hmac-sha256 secret signing-input)))))
