package log

import (
	"context"
	"io"
	"testing"
)

func TestRuntimeLevelPreparationDoesNotPublish(t *testing.T) {
	factory := NewDefaultFactory(context.Background(), Formatter{}, io.Discard, "", nil, false)
	factory.SetLevel(LevelInfo)
	publish, err := PrepareRuntimeLevel(factory, "debug")
	if err != nil {
		t.Fatal(err)
	}
	if factory.Level() != LevelInfo {
		t.Fatal("preparation changed live level")
	}
	publish()
	if factory.Level() != LevelDebug {
		t.Fatal("publication did not update level")
	}
	if _, err := PrepareRuntimeLevel(factory, "invalid"); err == nil {
		t.Fatal("invalid level accepted")
	}
	if factory.Level() != LevelDebug {
		t.Fatal("invalid candidate changed live level")
	}
}

func TestRuntimeLevelEmptyRestoresOriginalDefault(t *testing.T) {
	factory := NewDefaultFactory(context.Background(), Formatter{}, io.Discard, "", nil, false)
	factory.SetLevel(LevelError)
	publish, err := PrepareRuntimeLevel(factory, "")
	if err != nil {
		t.Fatal(err)
	}
	publish()
	if factory.Level() != LevelTrace {
		t.Fatal("empty level default changed")
	}
}
