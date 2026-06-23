package main

import "testing"

func TestDetectOkhttpWithVersion(t *testing.T) {
	paths := []string{"libs/okhttp-4.9.0.jar", "okhttp3/OkHttpClient.class"}
	comps := detect(paths)
	var got *component
	for i := range comps {
		if comps[i].Name == "okhttp" {
			got = &comps[i]
		}
	}
	if got == nil {
		t.Fatalf("okhttp not detected in %v", comps)
	}
	if got.Version != "4.9.0" {
		t.Fatalf("expected version 4.9.0, got %q", got.Version)
	}
	want := "pkg:maven/com.squareup.okhttp3/okhttp@4.9.0"
	if got.Purl != want {
		t.Fatalf("purl: want %q got %q", want, got.Purl)
	}
}

func TestDetectNativeOpenssl(t *testing.T) {
	comps := detect([]string{"lib/arm64-v8a/libssl.so.1.1.1k"})
	found := false
	for _, c := range comps {
		if c.Name == "openssl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("openssl not detected: %v", comps)
	}
}

func TestNoFalsePositiveOnEmpty(t *testing.T) {
	if comps := detect([]string{"AndroidManifest.xml", "classes.dex"}); len(comps) != 0 {
		t.Fatalf("expected no components, got %v", comps)
	}
}

func TestComponentsSortedByName(t *testing.T) {
	comps := detect([]string{"okhttp3/X.class", "com/google/gson/Gson.class"})
	if len(comps) < 2 {
		t.Fatalf("expected >=2 components, got %v", comps)
	}
	if comps[0].Name > comps[1].Name {
		t.Fatalf("components not sorted: %v", comps)
	}
}
