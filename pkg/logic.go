package potash

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/glaslos/tlsh"
	emerald "github.com/mosajjal/emerald/dns"
	"github.com/mosajjal/potash/pkg/vptree"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// Malware is the representation of each sample as per the abuse.ch CSV file
type Malware struct {
	tlsh.TLSH     `gob:"-"` // this is a custom type, so we need to ignore it
	FirstSeen     string
	SHA256        string
	MD5           string
	SHA1          string
	Reporter      string
	FileName      string
	FileTypeGuess string
	MIMEType      string
	Signature     string
	ClamAV        string
	VTPercent     string
	ImpHash       string
	SSDeep        string
	TLSHRaw       string
	DistanceValue float64 // This is purely used to fill out the table/JSON when printing a Malware sample against a TLSH
}

// GobEncode provides a standard GOB encoding
// TODO: embed the default gob encoding and ignore the TLSH field
func (m Malware) GobEncode() ([]byte, error) {

	buf := bytes.Buffer{}
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(m.FirstSeen)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.SHA256)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.MD5)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.SHA1)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.Reporter)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.FileName)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.FileTypeGuess)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.MIMEType)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.Signature)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.ClamAV)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.VTPercent)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.ImpHash)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.SSDeep)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(m.TLSHRaw)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GobDecode provides a standard GOB decoding
func (m *Malware) GobDecode(data []byte) error {

	buf := bytes.Buffer{}
	buf.Write(data)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(&m.FirstSeen)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.SHA256)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.MD5)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.SHA1)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.Reporter)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.FileName)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.FileTypeGuess)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.MIMEType)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.Signature)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.ClamAV)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.VTPercent)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.ImpHash)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.SSDeep)
	if err != nil {
		return err
	}
	err = dec.Decode(&m.TLSHRaw)
	if err != nil {
		return err
	}
	// parse the TLSH string into a TLSH struct
	if hash, err := tlsh.ParseStringToTlsh(CleanHash(m.TLSHRaw)); err == nil {
		m.TLSH = *hash
	} else {
		return err
	}
	return nil
}

// Marshal provides a way to show a Malware sample in different formats
func (m Malware) Marshal(kind string) ([]byte, error) {
	switch kind {
	case "json":
		return json.Marshal(m)
	case "yaml":
		return yaml.Marshal(m)
	case "table":
		var b bytes.Buffer
		_ = io.Writer(&b)
		emerald.PrettyPrint(m, &b)
		return ioutil.ReadAll(&b)
	// default to JSON
	default:
		return json.Marshal(m)
	}
}

// Distance is a required function for Malware struct to make it a vptree interface
func (m Malware) Distance(tItem vptree.TreeItem) float64 {
	malware2 := tItem.(Malware)
	return float64(m.TLSH.Diff(&malware2.TLSH))
}

func (m Malware) String() string {
	return m.TLSH.String()
}

// CleanHash removes the first two characters if the string starts with T and removes the newline character
func CleanHash(hash string) string {
	// if the string starts with T, remove the first two characters
	if strings.HasPrefix(hash, "T") {
		hash = hash[2:]
	}
	// remove newline char
	hash = strings.Replace(hash, "\n", "", -1)
	return hash
}

// Generate gets a csv path and spits out a tree gob file. force is used to overwrite the existing file
func Generate(csvPath string, gobPath string, force bool) error {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.UpdateCharSet(spinner.CharSets[11])
	// only proceed if the file doesn't exist or force is true
	if _, err := os.Stat(gobPath); err != nil || force {
		s.Suffix = " generating tree..."
		s.Start()
		hashes := []vptree.TreeItem{}
		// read the csvPath as a CSV file
		// TODO: handle ZIP files
		csvFile, err := os.Open(csvPath)
		if err != nil {
			return err
		}
		defer csvFile.Close()
		// create a new reader
		reader := csv.NewReader(csvFile)
		reader.Comma = ','
		reader.Comment = '#'
		reader.FieldsPerRecord = 14
		reader.TrimLeadingSpace = true
		reader.LazyQuotes = true
		// since the header is commented out, we'll paste it here manually
		// first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh
		header := []string{"first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", "file_name", "file_type_guess", "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"}
		// read the rest of the file
		for {
			// read each record from csv
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			// create a map of the record
			m := make(map[string]string)
			for i, v := range record {
				m[header[i]] = v
			}
			// insert into list of hashes
			if m["tlsh"] == "" {
				log.Debug().Msgf("skipping sha256:%s because it has no TLSH", m["sha256_hash"])
				continue
			}
			mal := Malware{
				FirstSeen:     m["first_seen_utc"],
				SHA256:        m["sha256_hash"],
				MD5:           m["md5_hash"],
				SHA1:          m["sha1_hash"],
				Reporter:      m["reporter"],
				FileName:      m["file_name"],
				FileTypeGuess: m["file_type_guess"],
				MIMEType:      m["mime_type"],
				Signature:     m["signature"],
				ClamAV:        m["clamav"],
				VTPercent:     m["vtpercent"],
				ImpHash:       m["imphash"],
				SSDeep:        m["ssdeep"],
				TLSHRaw:       m["tlsh"],
			}
			if hash, err := tlsh.ParseStringToTlsh(CleanHash(mal.TLSHRaw)); err == nil {
				mal.TLSH = *hash
				hashes = append(hashes, mal)
			} else {
				log.Debug().Msgf("skipping tlsh:%s because it has an invalid TLSH", m["tlsh"]) //TODO: remove
			}
		}

		// create a tree from list of hashes
		tree := vptree.New(hashes)
		log.Printf("tree has %d items", tree.Length)

		// save the tree to the gob file
		gobFile, err := os.Create(gobPath)
		if err != nil {
			return err
		}
		defer gobFile.Close()

		fz := gzip.NewWriter(gobFile)
		defer fz.Close()

		encoder := gob.NewEncoder(fz)
		gob.Register(tree)
		gob.Register(Malware{})
		// gob.RegisterName("potash.Malware", Malware{})
		err = encoder.Encode(tree)
		if err != nil {
			return err
		}
	} else {
		log.Info().Msg("GOB file is present and force is false, exiting")
	}
	s.Stop()
	return nil
}

// LoadGOB loads a tree from a gob file
func LoadGOB(gobPath string) (*vptree.VPTree, error) {
	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	s.UpdateCharSet(spinner.CharSets[11])
	gobFile, err := os.Open(gobPath)
	if err != nil {
		return nil, err
	}
	defer gobFile.Close()
	s.Suffix = " loading from GOB..."
	s.Start()
	fz, err := gzip.NewReader(gobFile)
	if err != nil {
		return nil, err
	}
	defer fz.Close()
	decoder := gob.NewDecoder(fz)
	var tree *vptree.VPTree
	gob.Register(tree)
	gob.Register(Malware{})
	err = decoder.Decode(&tree)
	if err != nil {
		return nil, err
	}
	s.Stop()
	return tree, nil
}

// RunOnce reads the GOB path for a trie or creates a new one
func RunOnce(gobPath string, hashInput string, radius uint16, outFormat string) error {
	tree, err := LoadGOB(gobPath)
	if err != nil {
		return err
	}

	hashInput = CleanHash(hashInput)
	if hash, err := tlsh.ParseStringToTlsh(hashInput); err == nil {
		results, distances := tree.Search(Malware{TLSH: *hash}, int(radius))
		for i, r := range results {
			p := r.(Malware)
			p.DistanceValue = distances[i]
			// TODO: maybe a distance threshold?
			if o, err := p.Marshal(outFormat); err != nil {
				return err
			} else {
				fmt.Printf("%s\n", o)
			}
		}
	} else {
		return err
	}
	return nil
}

func RunInteractive(gobPath string, radius uint16, outFormat string) error {
	tree, err := LoadGOB(gobPath)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter TLSH: ")
		hashInput, _ := reader.ReadString('\n')

		hashInput = CleanHash(hashInput)
		if hash, err := tlsh.ParseStringToTlsh(hashInput); err == nil {
			results, distances := tree.Search(Malware{TLSH: *hash}, int(radius))
			for i, r := range results {
				p := r.(Malware)
				p.DistanceValue = distances[i]
				if o, err := p.Marshal(outFormat); err != nil {
					return err
				} else {
					fmt.Printf("%s\n", o)
				}
			}
		} else {
			return err
		}
		// break on ctrl-d
		if err == io.EOF {
			break
		}
	}
	return nil
}
