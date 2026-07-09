(ns oidc.adapters.jwt-rsa
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [oidc.adapters.jwks :as jwks])
  (:import [java.math BigInteger]
           [java.nio.charset StandardCharsets]
           [java.security KeyFactory KeyPairGenerator Signature]
           [java.security.interfaces RSAPrivateKey RSAPublicKey]
           [java.security.spec RSAPublicKeySpec]
           [java.util Base64]))

(defn b64url-encode [bytes]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes))

(defn- b64url-decode-bytes [s]
  (.decode (Base64/getUrlDecoder) s))

(defn- b64url-decode-string [s]
  (String. (b64url-decode-bytes s) StandardCharsets/UTF_8))

(defn- unsigned-bigint [b64]
  (BigInteger. 1 (b64url-decode-bytes b64)))

(defn- split-jwt [token]
  (let [parts (str/split token #"\.")]
    (when-not (= 3 (count parts))
      (throw (ex-info "invalid JWT compact serialization" {:parts (count parts)})))
    parts))

(defn- decode-part [decode-json part]
  (decode-json (b64url-decode-string part)))

(defn- now-seconds []
  (quot (System/currentTimeMillis) 1000))

(defn- audience-match? [expected aud]
  (if (sequential? aud)
    (boolean (some #{expected} aud))
    (= expected aud)))

(defn- claim-error [claims opts]
  (cond
    (and (:issuer opts) (not= (:issuer opts) (:iss claims))) :issuer
    (and (:audience opts) (not (audience-match? (:audience opts) (:aud claims)))) :audience
    (and (:exp claims) (<= (:exp claims) (or (:now opts) (now-seconds)))) :expired
    (and (:nbf claims) (> (:nbf claims) (or (:now opts) (now-seconds)))) :not-yet-valid
    :else nil))

(defn- jwk-key [jwk]
  (let [spec (RSAPublicKeySpec. (unsigned-bigint (:n jwk))
                                (unsigned-bigint (:e jwk)))]
    (.generatePublic (KeyFactory/getInstance "RSA") spec)))

(defn- matching-jwk [jwks header]
  (let [kid (:kid header)
        keys (or (:keys jwks) jwks)]
    (if kid
      (first (filter #(and (= "RSA" (:kty %))
                           (= kid (:kid %)))
                     keys))
      (first (filter #(= "RSA" (:kty %)) keys)))))

(defn- verify-signature? [public-key signing-input signature-bytes]
  (let [sig (doto (Signature/getInstance "SHA256withRSA")
              (.initVerify public-key)
              (.update (.getBytes signing-input StandardCharsets/UTF_8)))]
    (.verify sig signature-bytes)))

(defn rs256-verifier [jwks opts]
  (let [decode-json (or (:decode-json opts) edn/read-string)]
    (reify jwks/IJwksVerifier
      (verify-jwt! [_ token-ref call-opts]
        (try
          (let [[header-seg claims-seg sig-seg] (split-jwt token-ref)
                signing-input (str header-seg "." claims-seg)
                header (decode-part decode-json header-seg)
                claims (decode-part decode-json claims-seg)
                jwk (matching-jwk (or (:jwks call-opts) jwks) header)
                err (claim-error claims call-opts)]
            (cond
              (not= "RS256" (:alg header))
              {:error :unsupported-algorithm :alg (:alg header)}
              (nil? jwk)
              {:error :missing-jwk :kid (:kid header)}
              (not (verify-signature? (jwk-key jwk) signing-input (b64url-decode-bytes sig-seg)))
              {:error :invalid-signature}
              err
              (assoc claims :error err)
              :else
              (assoc claims :jwt-ref token-ref)))
          (catch Exception e
            {:error :invalid-jwt
             :message (ex-message e)}))))))

(defn generate-rsa-keypair []
  (.generateKeyPair (doto (KeyPairGenerator/getInstance "RSA")
                      (.initialize 2048))))

(defn jwk-from-public-key
  ([public-key] (jwk-from-public-key public-key {}))
  ([^RSAPublicKey public-key opts]
   {:kty "RSA"
    :kid (:kid opts)
    :alg "RS256"
    :use "sig"
    :n (b64url-encode (.toByteArray (.getModulus public-key)))
    :e (b64url-encode (.toByteArray (.getPublicExponent public-key)))}))

(defn- sign-rsa [^RSAPrivateKey private-key signing-input]
  (let [sig (doto (Signature/getInstance "SHA256withRSA")
              (.initSign private-key)
              (.update (.getBytes signing-input StandardCharsets/UTF_8)))]
    (.sign sig)))

(defn sign-rs256 [private-key header claims]
  (let [header-seg (b64url-encode (.getBytes (pr-str header) StandardCharsets/UTF_8))
        claims-seg (b64url-encode (.getBytes (pr-str claims) StandardCharsets/UTF_8))
        signing-input (str header-seg "." claims-seg)]
    (str signing-input "." (b64url-encode (sign-rsa private-key signing-input)))))
