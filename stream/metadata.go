package stream

//	===============
//	STREAM METADATA
//	===============

//	Metadata about the encrypted stream
type StreamMeta struct {
	//	Initialization Vector for the cryptographic function
	IV []byte
	//	HMAC hash of the stream
	Hash []byte
}

//	Returns the encrypted streams metadata for use in decrypting. This should be called after the stream is finished
func (s *StreamEncrypter) Meta() StreamMeta {
	return StreamMeta{IV: s.IV, Hash: s.MAC.Sum(nil)}
}
