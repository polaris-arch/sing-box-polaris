package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/badversion"
)

type gitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type githubReader func(string, any) error

func githubJSON(endpoint string, target any) error {
	file, err := os.CreateTemp("", "polaris-github-metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := readGitHub(endpoint, file, 32<<20, nil, defaultReadLimits, nil); err != nil {
		return err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	return uniqueJSON(file, target)
}

func remoteTagIdentity(tag, source, expectedObject string, read githubReader) (string, error) {
	if !strings.HasPrefix(tag, "v") || !badversion.IsCanonicalPolaris(strings.TrimPrefix(tag, "v")) {
		return "", fmt.Errorf("versioned source tag required")
	}
	if !sourceCommit.MatchString(source) || expectedObject != "" && !sourceCommit.MatchString(expectedObject) {
		return "", fmt.Errorf("full source SHA and expected tag object required")
	}
	var ref struct {
		Object gitObject `json:"object"`
	}
	if err := read("repos/"+repository+"/git/ref/tags/"+tag, &ref); err != nil {
		return "", err
	}
	if ref.Object.Type != "tag" || !sourceCommit.MatchString(ref.Object.SHA) {
		return "", fmt.Errorf("annotated tag required")
	}
	object := ref.Object.SHA
	if expectedObject != "" && object != expectedObject {
		return "", fmt.Errorf("source tag object moved")
	}
	var annotated struct {
		SHA    string    `json:"sha"`
		Tag    string    `json:"tag"`
		Object gitObject `json:"object"`
	}
	if err := read("repos/"+repository+"/git/tags/"+object, &annotated); err != nil {
		return "", err
	}
	if annotated.SHA != object || annotated.Tag != tag || annotated.Object.Type != "commit" || annotated.Object.SHA != source {
		return "", fmt.Errorf("annotated tag must directly identify dispatch source")
	}
	return object, nil
}

func verifyCheckout(root, tag, source, expectedObject string, read githubReader) (string, error) {
	if os.Getenv("GITHUB_REPOSITORY") != repository || os.Getenv("GITHUB_REPOSITORY_ID") != repositoryID {
		return "", fmt.Errorf("wrong producer repository")
	}
	if source != os.Getenv("GITHUB_SHA") {
		return "", fmt.Errorf("expected source differs from dispatch SHA")
	}
	head, err := git(root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(head)) != source {
		return "", fmt.Errorf("actual producer checkout differs from dispatch SHA")
	}
	status, err := git(root, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(status))) != 0 {
		return "", fmt.Errorf("tracked producer source is dirty")
	}
	object, err := remoteTagIdentity(tag, source, expectedObject, read)
	if err != nil {
		return "", err
	}
	for _, check := range []struct {
		args []string
		want string
		err  string
	}{
		{[]string{"cat-file", "-t", "refs/tags/" + tag}, "tag", "local annotated tag missing"},
		{[]string{"rev-parse", "refs/tags/" + tag}, object, "local and remote tag objects differ"},
		{[]string{"rev-parse", "refs/tags/" + tag + "^{commit}"}, source, "local tag differs from dispatch source"},
	} {
		actual, err := git(root, check.args...)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(actual)) != check.want {
			return "", fmt.Errorf("%s", check.err)
		}
	}
	return object, nil
}

func releaseIdentity(args []string) error {
	flags := flag.NewFlagSet("release-identity", flag.ContinueOnError)
	tag := flags.String("tag", "", "annotated version tag")
	source := flags.String("source", os.Getenv("GITHUB_SHA"), "dispatch commit")
	expected := flags.String("expected-tag-object", "", "reviewed tag object")
	output := flags.String("github-output", "", "native action output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected release-identity arguments")
	}
	if os.Getenv("GITHUB_REF_TYPE") != "tag" || os.Getenv("GITHUB_REF_NAME") != *tag {
		return fmt.Errorf("release identity requires the exact dispatched tag")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	object, err := verifyCheckout(root, *tag, *source, *expected, githubJSON)
	if err != nil {
		return err
	}
	if *output != "" {
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(file, "version=%s\ntag_object=%s\n", strings.TrimPrefix(*tag, "v"), object)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return writeJSON(os.Stdout, map[string]string{"sourceCommit": *source, "tag": *tag, "tagObject": object})
}
