//! SigV4 signer against published examples and an independent implementation.
//!
//! Published vectors: the `get-vanilla` case of the SigV4 test suite and the four S3 examples of
//! the S3 API reference (GET object with a range, PUT object, GET bucket lifecycle, list objects),
//! signed with the documented example credentials. Their expected signatures are the published
//! ones; the canonical-request hashes were derived with the independent implementation below.
//!
//! The last two vectors (a PUT with a session token, SSE headers and an encoded key; a listing
//! with a continuation token and characters that need encoding) have no published value. Their
//! expected results were produced once by a separate python3 `hmac`/`hashlib` implementation
//! written for this test (`quote` for percent-encoding, no shared code with the signer) and are
//! pinned here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browserx_store::sigv4::{SigningRequest, canonical_query, sign, uri_encode};
use sha2::{Digest, Sha256};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[test]
fn suite_get_vanilla() {
    let signed = sign(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        &SigningRequest {
            method: "GET",
            path: "/",
            query: &[],
            headers: &[
                ("Host", "example.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
            ],
            payload_sha256: EMPTY_SHA256,
            amz_date: "20150830T123600Z",
            region: "us-east-1",
            service: "service",
        },
    )
    .unwrap();
    assert_eq!(
        signed.canonical_request,
        "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        signed.string_to_sign,
        "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
         bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    );
    assert_eq!(
        signed.signature,
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    assert_eq!(
        signed.authorization("AKIDEXAMPLE"),
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
}

const S3_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const S3_DATE: &str = "20130524T000000Z";

fn s3_request<'a>(
    method: &'a str,
    path: &'a str,
    query: &'a [(&'a str, &'a str)],
    headers: &'a [(&'a str, &'a str)],
    payload: &'a str,
) -> SigningRequest<'a> {
    SigningRequest {
        method,
        path,
        query,
        headers,
        payload_sha256: payload,
        amz_date: S3_DATE,
        region: "us-east-1",
        service: "s3",
    }
}

#[test]
fn s3_get_object_with_range() {
    let signed = sign(
        S3_SECRET,
        &s3_request(
            "GET",
            "/test.txt",
            &[],
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", S3_DATE),
            ],
            EMPTY_SHA256,
        ),
    )
    .unwrap();
    assert_eq!(
        signed.signed_headers,
        "host;range;x-amz-content-sha256;x-amz-date"
    );
    assert_eq!(
        sha256_hex(signed.canonical_request.as_bytes()),
        "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
    );
    assert_eq!(
        signed.signature,
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn s3_put_object_with_body_and_encoded_key() {
    let body = b"Welcome to Amazon S3.";
    let payload = sha256_hex(body);
    assert_eq!(
        payload,
        "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    );
    let signed = sign(
        S3_SECRET,
        &s3_request(
            "PUT",
            "/test$file.text",
            &[],
            &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", &payload),
                ("x-amz-date", S3_DATE),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            &payload,
        ),
    )
    .unwrap();
    assert!(
        signed
            .canonical_request
            .starts_with("PUT\n/test%24file.text\n\n")
    );
    assert_eq!(
        sha256_hex(signed.canonical_request.as_bytes()),
        "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
    );
    assert_eq!(
        signed.signature,
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    );
}

#[test]
fn s3_get_bucket_lifecycle_empty_query_value() {
    let signed = sign(
        S3_SECRET,
        &s3_request(
            "GET",
            "/",
            &[("lifecycle", "")],
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", S3_DATE),
            ],
            EMPTY_SHA256,
        ),
    )
    .unwrap();
    assert!(signed.canonical_request.starts_with("GET\n/\nlifecycle=\n"));
    assert_eq!(
        signed.signature,
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    );
}

#[test]
fn s3_list_objects_sorts_query() {
    // Parameters are given out of order on purpose.
    let signed = sign(
        S3_SECRET,
        &s3_request(
            "GET",
            "/",
            &[("prefix", "J"), ("max-keys", "2")],
            &[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", S3_DATE),
            ],
            EMPTY_SHA256,
        ),
    )
    .unwrap();
    assert!(
        signed
            .canonical_request
            .starts_with("GET\n/\nmax-keys=2&prefix=J\n")
    );
    assert_eq!(
        signed.signature,
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    );
}

#[test]
fn cross_checked_put_with_token_sse_and_metadata() {
    let payload = sha256_hex(b"sealed bytes \x00\xff");
    assert_eq!(
        payload,
        "4078a6e94b10c452117b08d1d206d5dd8f99e8ffde0927ba048567a88870f108"
    );
    let signed = sign(
        "bx/secret+key=EXAMPLE",
        &SigningRequest {
            method: "PUT",
            path: "/bucket-one/browserx/snapshots/prf_ab/00000000000000000007.snap",
            query: &[],
            headers: &[
                ("host", "127.0.0.1:9000"),
                ("content-type", "application/octet-stream"),
                ("x-amz-content-sha256", &payload),
                ("x-amz-date", "20260102T030405Z"),
                ("x-amz-security-token", "TOKEN/with+chars=="),
                ("x-amz-meta-bx-meta", "eyJhIjoxfQ=="),
                ("x-amz-server-side-encryption", "aws:kms"),
                ("x-amz-server-side-encryption-aws-kms-key-id", "key-1"),
                ("if-none-match", "*"),
            ],
            payload_sha256: &payload,
            amz_date: "20260102T030405Z",
            region: "eu-west-1",
            service: "s3",
        },
    )
    .unwrap();
    assert_eq!(
        signed.signed_headers,
        "content-type;host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-meta-bx-meta;\
         x-amz-security-token;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id"
    );
    assert_eq!(
        sha256_hex(signed.canonical_request.as_bytes()),
        "b0ed1b33f984349e599c1b3bfab9804eed34b2c9f11e9d7a854e481d10ea7cb9"
    );
    assert_eq!(
        signed.signature,
        "c0f43c820696befb3f06f910726ea41494e33af27af0347d96dfbf8025d8de14"
    );
}

#[test]
fn cross_checked_list_with_token_and_encoded_values() {
    let signed = sign(
        "bx/secret+key=EXAMPLE",
        &SigningRequest {
            method: "GET",
            path: "/bucket-one",
            query: &[
                ("list-type", "2"),
                ("max-keys", "1000"),
                ("prefix", "browserx/snap shots/é+&"),
                (
                    "continuation-token",
                    "1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=",
                ),
            ],
            headers: &[
                ("host", "127.0.0.1:9000"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20260102T030405Z"),
            ],
            payload_sha256: EMPTY_SHA256,
            amz_date: "20260102T030405Z",
            region: "eu-west-1",
            service: "s3",
        },
    )
    .unwrap();
    assert_eq!(
        signed.canonical_request.lines().nth(2).unwrap(),
        "continuation-token=1ueGcxLPRx1Tr%2FXYExHnhbYLgveDs2J%2Fwm36Hy4vbOwM%3D&list-type=2&max-keys=1000&\
         prefix=browserx%2Fsnap%20shots%2F%C3%A9%2B%26"
    );
    assert_eq!(
        signed.signature,
        "ae20de8bda9746d85c5b533ef35c352e97cef7f9a4f19e537f05f111f55368eb"
    );
}

#[test]
fn encoding_rules() {
    assert_eq!(uri_encode("a b/c~d_e-f.g", true), "a%20b/c~d_e-f.g");
    assert_eq!(uri_encode("a/b", false), "a%2Fb");
    assert_eq!(uri_encode("é", true), "%C3%A9");
    assert_eq!(uri_encode("+&=$", true), "%2B%26%3D%24");
    // Sorted by encoded name, then value; empty values keep the `=`.
    assert_eq!(
        canonical_query(&[("b", "2"), ("a", "z"), ("a", "1"), ("c", "")]),
        "a=1&a=z&b=2&c="
    );
}

#[test]
fn header_values_are_trimmed_and_collapsed() {
    let a = sign(
        "secret",
        &SigningRequest {
            method: "GET",
            path: "/",
            query: &[],
            headers: &[("host", "h"), ("x-amz-meta-a", "  one   two ")],
            payload_sha256: EMPTY_SHA256,
            amz_date: "20260102T030405Z",
            region: "us-east-1",
            service: "s3",
        },
    )
    .unwrap();
    assert!(a.canonical_request.contains("\nx-amz-meta-a:one two\n"));
}
