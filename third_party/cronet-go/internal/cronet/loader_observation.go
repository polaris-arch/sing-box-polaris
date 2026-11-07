package cronet

// LibraryObservation describes bytes held by the loader. It is diagnostic data,
// never admission authority. Hashing occurs only on an explicit observation.
type LibraryObservation struct {
	Path      string
	Bytes     int64
	SHA256    string
	Selection string
	Windows   *WindowsLibraryObservation
}

// WindowsLibraryObservation binds a real loaded image mapping to the object
// retained across LoadLibraryEx. It carries no execution authority.
type WindowsLibraryObservation struct {
	VolumeSerial       string `json:"volumeSerial"`
	FileID             string `json:"fileId"`
	NativePath         string `json:"nativePath"`
	ModulePath         string `json:"modulePath"`
	MappedPath         string `json:"mappedPath"`
	ModuleBase         string `json:"moduleBase"`
	MemoryType         uint32 `json:"memoryType"`
	LoadFlags          uint32 `json:"loadFlags"`
	ParentFileID       string `json:"parentFileId"`
	ParentVolumeSerial string `json:"parentVolumeSerial"`
	ShareReadOnly      bool   `json:"shareReadOnly"`
}
