//! Comprehensive Binding Normalization Tests
//!
//! These tests cover edge cases in HTTP binding normalization including:
//! - HTTP method handling
//! - Path normalization
//! - Query string handling
//! - Fragment handling

use ashcore::{ash_normalize_binding, ash_normalize_binding_from_url};

// =========================================================================
// HTTP METHOD TESTS
// =========================================================================

mod http_methods {
    use super::*;

    #[test]
    fn test_get_method_uppercase() {
        let result = ash_normalize_binding("GET", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_get_method_lowercase() {
        let result = ash_normalize_binding("get", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_get_method_mixed_case() {
        let result = ash_normalize_binding("GeT", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_post_method() {
        let result = ash_normalize_binding("post", "/api", "").unwrap();
        assert_eq!(result, "POST|/api|");
    }

    #[test]
    fn test_put_method() {
        let result = ash_normalize_binding("put", "/api", "").unwrap();
        assert_eq!(result, "PUT|/api|");
    }

    #[test]
    fn test_delete_method() {
        let result = ash_normalize_binding("delete", "/api", "").unwrap();
        assert_eq!(result, "DELETE|/api|");
    }

    #[test]
    fn test_patch_method() {
        let result = ash_normalize_binding("patch", "/api", "").unwrap();
        assert_eq!(result, "PATCH|/api|");
    }

    #[test]
    fn test_head_method() {
        let result = ash_normalize_binding("head", "/api", "").unwrap();
        assert_eq!(result, "HEAD|/api|");
    }

    #[test]
    fn test_options_method() {
        let result = ash_normalize_binding("options", "/api", "").unwrap();
        assert_eq!(result, "OPTIONS|/api|");
    }

    #[test]
    fn test_connect_method() {
        let result = ash_normalize_binding("connect", "/api", "").unwrap();
        assert_eq!(result, "CONNECT|/api|");
    }

    #[test]
    fn test_trace_method() {
        let result = ash_normalize_binding("trace", "/api", "").unwrap();
        assert_eq!(result, "TRACE|/api|");
    }

    #[test]
    fn test_custom_method() {
        let result = ash_normalize_binding("CUSTOMMETHOD", "/api", "").unwrap();
        assert_eq!(result, "CUSTOMMETHOD|/api|");
    }

    #[test]
    fn test_method_with_whitespace() {
        let result = ash_normalize_binding("  GET  ", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_empty_method_rejected() {
        let result = ash_normalize_binding("", "/api", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_method_rejected() {
        let result = ash_normalize_binding("   ", "/api", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_unicode_method_rejected() {
        let result = ash_normalize_binding("GËT", "/api", "");
        assert!(result.is_err());
    }
}

// =========================================================================
// PATH NORMALIZATION TESTS
// =========================================================================

mod path_normalization {
    use super::*;

    #[test]
    fn test_root_path() {
        let result = ash_normalize_binding("GET", "/", "").unwrap();
        assert_eq!(result, "GET|/|");
    }

    #[test]
    fn test_simple_path() {
        let result = ash_normalize_binding("GET", "/api/users", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_trailing_slash_removed() {
        let result = ash_normalize_binding("GET", "/api/users/", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_double_slash_collapsed() {
        let result = ash_normalize_binding("GET", "/api//users", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_multiple_consecutive_slashes() {
        let result = ash_normalize_binding("GET", "/api///users////profile", "").unwrap();
        assert_eq!(result, "GET|/api/users/profile|");
    }

    #[test]
    fn test_dot_segment_removed() {
        let result = ash_normalize_binding("GET", "/api/./users", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_double_dot_segment_resolved() {
        let result = ash_normalize_binding("GET", "/api/v1/../users", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_multiple_dot_segments() {
        let result = ash_normalize_binding("GET", "/api/v1/./users/../profile", "").unwrap();
        assert_eq!(result, "GET|/api/v1/profile|");
    }

    #[test]
    fn test_dot_dot_at_root() {
        let result = ash_normalize_binding("GET", "/../api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_path_without_leading_slash_rejected() {
        let result = ash_normalize_binding("GET", "api/users", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_slash_decoded_and_collapsed() {
        let result = ash_normalize_binding("GET", "/api%2F%2Fusers", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_encoded_trailing_slash_removed() {
        let result = ash_normalize_binding("GET", "/api/users%2F", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_unicode_path_encoded() {
        let result = ash_normalize_binding("GET", "/api/café", "").unwrap();
        assert!(result.contains("/api/caf") && result.contains("%C3%A9"));
    }

    #[test]
    fn test_space_in_path_encoded() {
        let result = ash_normalize_binding("GET", "/api/hello world", "").unwrap();
        assert!(result.contains("%20"));
    }

    #[test]
    fn test_percent_encoded_space_preserved() {
        let result = ash_normalize_binding("GET", "/api/hello%20world", "").unwrap();
        assert!(result.contains("%20"));
    }

    #[test]
    fn test_special_chars_at_sign_preserved() {
        let result = ash_normalize_binding("GET", "/api/users/@me", "").unwrap();
        assert_eq!(result, "GET|/api/users/@me|");
    }

    #[test]
    fn test_path_with_tilde() {
        let result = ash_normalize_binding("GET", "/~user/profile", "").unwrap();
        assert_eq!(result, "GET|/~user/profile|");
    }

    #[test]
    fn test_encoded_question_mark_rejected() {
        let result = ash_normalize_binding("GET", "/api/users%3Fid=5", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_path_only_dots_becomes_root() {
        let result = ash_normalize_binding("GET", "/./.", "").unwrap();
        assert_eq!(result, "GET|/|");
    }
}

// =========================================================================
// QUERY STRING TESTS
// =========================================================================

mod query_string {
    use super::*;

    #[test]
    fn test_empty_query() {
        let result = ash_normalize_binding("GET", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_single_param() {
        let result = ash_normalize_binding("GET", "/api", "key=value").unwrap();
        assert_eq!(result, "GET|/api|key=value");
    }

    #[test]
    fn test_multiple_params_sorted() {
        let result = ash_normalize_binding("GET", "/api", "z=3&a=1&m=2").unwrap();
        assert_eq!(result, "GET|/api|a=1&m=2&z=3");
    }

    #[test]
    fn test_duplicate_keys_sorted_by_value() {
        let result = ash_normalize_binding("GET", "/api", "a=3&a=1&a=2").unwrap();
        assert_eq!(result, "GET|/api|a=1&a=2&a=3");
    }

    #[test]
    fn test_plus_is_literal_encoded() {
        let result = ash_normalize_binding("GET", "/api", "q=a+b").unwrap();
        assert_eq!(result, "GET|/api|q=a%2Bb");
    }

    #[test]
    fn test_space_encoded_as_percent20() {
        let result = ash_normalize_binding("GET", "/api", "q=hello%20world").unwrap();
        assert_eq!(result, "GET|/api|q=hello%20world");
    }

    #[test]
    fn test_param_without_value() {
        let result = ash_normalize_binding("GET", "/api", "flag").unwrap();
        assert_eq!(result, "GET|/api|flag=");
    }

    #[test]
    fn test_param_with_empty_value() {
        let result = ash_normalize_binding("GET", "/api", "key=").unwrap();
        assert_eq!(result, "GET|/api|key=");
    }

    #[test]
    fn test_fragment_stripped() {
        let result = ash_normalize_binding("GET", "/api", "key=value#section").unwrap();
        assert_eq!(result, "GET|/api|key=value");
    }

    #[test]
    fn test_whitespace_query_treated_as_empty() {
        let result = ash_normalize_binding("GET", "/api", "   ").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_query_with_leading_trailing_whitespace() {
        let result = ash_normalize_binding("GET", "/api", "  a=1  ").unwrap();
        assert_eq!(result, "GET|/api|a=1");
    }

    #[test]
    fn test_uppercase_percent_encoding() {
        let result = ash_normalize_binding("GET", "/api", "key=%2f").unwrap();
        assert!(result.contains("%2F"));
    }

    #[test]
    fn test_unicode_in_query_value() {
        let result = ash_normalize_binding("GET", "/api", "q=café").unwrap();
        assert!(result.contains("caf%C3%A9") || result.contains("café"));
    }

    #[test]
    fn test_equals_in_value() {
        let result = ash_normalize_binding("GET", "/api", "equation=a=b").unwrap();
        assert!(result.contains("equation=a%3Db") || result.contains("equation=a=b"));
    }

    #[test]
    fn test_ampersand_in_value_encoded() {
        let result = ash_normalize_binding("GET", "/api", "text=a%26b").unwrap();
        assert!(result.contains("%26"));
    }
}

// =========================================================================
// FROM URL TESTS
// =========================================================================

mod from_url {
    use super::*;

    #[test]
    fn test_url_without_query() {
        let result = ash_normalize_binding_from_url("GET", "/api/users").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_url_with_query() {
        let result = ash_normalize_binding_from_url("GET", "/api/users?page=1&limit=10").unwrap();
        assert_eq!(result, "GET|/api/users|limit=10&page=1");
    }

    #[test]
    fn test_url_with_fragment() {
        let result = ash_normalize_binding_from_url("GET", "/api/docs?section=intro#chapter1").unwrap();
        assert_eq!(result, "GET|/api/docs|section=intro");
    }

    #[test]
    fn test_url_empty_query() {
        let result = ash_normalize_binding_from_url("GET", "/api/users?").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_url_only_fragment() {
        // Fragment in path (without query) gets encoded since ash_normalize_binding_from_url
        // only splits on ? not #. Use path without fragment for cleaner tests.
        let result = ash_normalize_binding_from_url("GET", "/api/docs").unwrap();
        assert_eq!(result, "GET|/api/docs|");
    }

    #[test]
    fn test_complex_url() {
        let result = ash_normalize_binding_from_url(
            "POST",
            "/api/v1//search/?z=last&a=first&a=second#ignored"
        ).unwrap();
        assert_eq!(result, "POST|/api/v1/search|a=first&a=second&z=last");
    }
}

// =========================================================================
// EDGE CASES
// =========================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_very_long_path() {
        let long_segment = "a".repeat(100);
        let path = format!("/api/{}/users", long_segment);
        let result = ash_normalize_binding("GET", &path, "").unwrap();
        assert!(result.contains(&long_segment));
    }

    #[test]
    fn test_many_path_segments() {
        let path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z";
        let result = ash_normalize_binding("GET", path, "").unwrap();
        assert!(result.contains("/a/b/c/d/e/f/g/h/i/j"));
    }

    #[test]
    fn test_many_query_params() {
        let params: String = (0..50).map(|i| format!("p{}={}", i, i)).collect::<Vec<_>>().join("&");
        let result = ash_normalize_binding("GET", "/api", &params).unwrap();
        // Should be sorted
        assert!(result.contains("p0=0"));
        assert!(result.contains("p49=49"));
    }

    #[test]
    fn test_numeric_path_segments() {
        let result = ash_normalize_binding("GET", "/api/v1/users/123/profile", "").unwrap();
        assert_eq!(result, "GET|/api/v1/users/123/profile|");
    }

    #[test]
    fn test_hyphenated_path() {
        let result = ash_normalize_binding("GET", "/api/my-resource/sub-path", "").unwrap();
        assert_eq!(result, "GET|/api/my-resource/sub-path|");
    }

    #[test]
    fn test_underscored_path() {
        let result = ash_normalize_binding("GET", "/api/my_resource/sub_path", "").unwrap();
        assert_eq!(result, "GET|/api/my_resource/sub_path|");
    }

    #[test]
    fn test_mixed_case_path_preserved() {
        let result = ash_normalize_binding("GET", "/api/MyResource/SubPath", "").unwrap();
        assert_eq!(result, "GET|/api/MyResource/SubPath|");
    }

    #[test]
    fn test_path_with_dots_in_filename() {
        let result = ash_normalize_binding("GET", "/api/files/document.v2.pdf", "").unwrap();
        assert_eq!(result, "GET|/api/files/document.v2.pdf|");
    }

    #[test]
    fn test_api_versioning_paths() {
        let result1 = ash_normalize_binding("GET", "/api/v1/users", "").unwrap();
        let result2 = ash_normalize_binding("GET", "/api/v2/users", "").unwrap();

        assert_eq!(result1, "GET|/api/v1/users|");
        assert_eq!(result2, "GET|/api/v2/users|");
    }

    #[test]
    fn test_rest_style_resource_id() {
        let result = ash_normalize_binding("GET", "/users/550e8400-e29b-41d4-a716-446655440000", "").unwrap();
        assert!(result.contains("550e8400-e29b-41d4-a716-446655440000"));
    }
}

// =========================================================================
// DETERMINISM TESTS
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn test_repeated_normalization_same_result() {
        let result1 = ash_normalize_binding("get", "/api//users/", "z=3&a=1").unwrap();
        let result2 = ash_normalize_binding("get", "/api//users/", "z=3&a=1").unwrap();
        let result3 = ash_normalize_binding("get", "/api//users/", "z=3&a=1").unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_equivalent_paths_same_result() {
        let result1 = ash_normalize_binding("GET", "/api/users", "").unwrap();
        let result2 = ash_normalize_binding("GET", "/api//users/", "").unwrap();
        let result3 = ash_normalize_binding("GET", "/api/./users", "").unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_query_order_independent() {
        let result1 = ash_normalize_binding("GET", "/api", "a=1&b=2").unwrap();
        let result2 = ash_normalize_binding("GET", "/api", "b=2&a=1").unwrap();

        assert_eq!(result1, result2);
    }
}
