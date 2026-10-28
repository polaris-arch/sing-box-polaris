package network

import "testing"

type metadataBoundaryFixture struct {
	reader        ReaderBufferMetadata
	writer        WriterBufferMetadata
	reads, writes int
}

func (f *metadataBoundaryFixture) ReaderBufferMetadata() ReaderBufferMetadata {
	f.reads++
	return f.reader
}
func (f *metadataBoundaryFixture) WriterBufferMetadata() WriterBufferMetadata {
	f.writes++
	return f.writer
}

// Complete-boundary metadata must win over every scalar or carrier hook.
func (*metadataBoundaryFixture) Upstream() any       { panic("carrier escape") }
func (*metadataBoundaryFixture) UpstreamReader() any { panic("reader escape") }
func (*metadataBoundaryFixture) UpstreamWriter() any { panic("writer escape") }
func (*metadataBoundaryFixture) FrontHeadroom() int  { panic("double count") }
func (*metadataBoundaryFixture) RearHeadroom() int   { panic("double count") }
func (*metadataBoundaryFixture) ReaderOverhead() int { panic("double count") }
func (*metadataBoundaryFixture) ReaderMTU() int      { panic("double count") }
func (*metadataBoundaryFixture) WriterMTU() int      { panic("double count") }
func (*metadataBoundaryFixture) LazyHeadroom() bool  { panic("directional state lost") }

func TestBufferMetadataBoundaryHasPriorityAndNoCarrierAccess(t *testing.T) {
	f := &metadataBoundaryFixture{reader: ReaderBufferMetadata{Overhead: 7, MTU: 1500}, writer: WriterBufferMetadata{FrontHeadroom: 11, RearHeadroom: 13, MTU: 1300}}
	if CalculateFrontHeadroom(f) != 11 || CalculateRearHeadroom(f) != 13 || CalculateReaderOverhead(f) != 7 || calculateReaderMTU(f) != 1500 || calculateWriterMTU(f) != 1300 {
		t.Fatal("boundary fields differ")
	}
	if f.reads != 2 || f.writes != 3 {
		t.Fatal("boundary resampled")
	}
	f.reader.Lazy = true
	f.writer.Lazy = true
	if CalculateFrontHeadroom(f) != DefaultHeadroom || CalculateRearHeadroom(f) != DefaultHeadroom || CalculateReaderOverhead(f) != DefaultHeadroom || calculateReaderMTU(f) != 0 || calculateWriterMTU(f) != 0 {
		t.Fatal("lazy reset differs")
	}
	if CalculateReaderBufferMetadata(f) != (ReaderBufferMetadata{Overhead: DefaultHeadroom, Lazy: true}) || CalculateWriterBufferMetadata(f) != (WriterBufferMetadata{FrontHeadroom: DefaultHeadroom, RearHeadroom: DefaultHeadroom, Lazy: true}) {
		t.Fatal("lazy boundary aggregate differs")
	}
}

func TestBufferMetadataEmptyContractRemainsEmpty(t *testing.T) {
	for _, value := range []any{nil, struct{}{}} {
		if CalculateReaderBufferMetadata(value) != (ReaderBufferMetadata{}) || CalculateWriterBufferMetadata(value) != (WriterBufferMetadata{}) {
			t.Fatal("empty metadata changed")
		}
		if CalculateFrontHeadroom(value) != 0 || CalculateRearHeadroom(value) != 0 || CalculateReaderOverhead(value) != 0 || CalculateMTU(value, value) != 0 {
			t.Fatal("empty scalar changed")
		}
	}
}
