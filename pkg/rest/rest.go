// Package rest provides a simple REST API for the potash package
//
// The API is a single endpoint that takes two parameters:
// - hash: the hash to search for
// - radius: the radius to search within
//
// The API returns a JSON array of results, each result is a JSON object with the following fields:
// - FirstSeen: the date the malware was first seen
// - SHA256: the SHA256 hash of the malware
// - MD5: the MD5 hash of the malware
// - SHA1: the SHA1 hash of the malware
// - Reporter: the name of the reporter
// - FileName: the name of the file
// - FileTypeGuess: the guessed file type
// - MIMEType: the MIME type of the file
// - Signature: the signature of the file
// - ClamAV: the ClamAV result
// - VTPercent: the VirusTotal result
// - ImpHash: the ImpHash of the file
// - SSDeep: the SSDeep hash of the file
// - TLSHRaw: the TLSH hash of the file
// - DistanceValue: the distance between the hash and the result
// example usage:
// curl -X GET "http://localhost:5555/?hash=T1DB52C083FA3DF4C75D587A74009B8EA3065B9E4E266D8F9C4FB974091736CE2E401A4A&radius=1"
// if a basepath is set, it is prepended to the endpoint
// example usage with basepath:
// curl -X GET "http://localhost:5555/basepath?hash=T1DB52C083FA3DF4C75D587A74009B8EA3065B9E4E266D8F9C4FB974091736CE2E401A4A&radius=1"

package rest

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/glaslos/tlsh"
	potash "github.com/mosajjal/potash/pkg"
)

func RunRest(gobPath, listenAddr, basePath, tlsCert, tlsKey string) error {
	// load the tree
	tree, err := potash.LoadGOB(gobPath)
	if err != nil {
		return err
	}
	// start the server
	r := gin.Default()
	r.GET(basePath, func(c *gin.Context) {
		hashInput := c.Query("hash")
		if hashInput == "" {
			c.JSON(400, gin.H{"error": "missing hash"})
			return
		}
		radius := c.Query("radius")
		if radius == "" {
			radius = "10"
		}
		rad, err := strconv.ParseUint(radius, 10, 16)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		hashInput = potash.CleanHash(hashInput)
		if hash, err := tlsh.ParseStringToTlsh(hashInput); err == nil {
			results, distances := tree.Search(potash.Malware{TLSH: *hash}, int(rad))
			output := make([]potash.Malware, len(results))
			for i, r := range results {
				p := r.(potash.Malware)
				p.DistanceValue = distances[i]
				output[i] = p
			}
			c.JSON(200, output)
		} else {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
	})
	if tlsCert != "" && tlsKey != "" {
		return r.RunTLS(listenAddr, tlsCert, tlsKey)
	} else {
		return r.Run(listenAddr)
	}

}
