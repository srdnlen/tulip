package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"go-importer/internal/pkg/db"

	"github.com/gofrs/uuid/v5"
	"github.com/tidwall/gjson"
)

var eve_file = flag.String("eve", "", "Eve file/socket path to watch for suricata's tags")
var timescale = flag.String("timescale", "", "Timescale connection string (e. g. postgres://usr:pwd@host:5432/tulip)")
var tag_flowbits = flag.Bool("flowbits", true, "Tag flows with their flowbits")
var rescan_period = flag.Int("t", 30, "rescan period (in seconds).")

// Concurrency Settings
var numWorkers = 10
var channelBufferSize = 5000 // Can hold 5000 alerts in memory during a burst

var g_db *db.Database

func init() {
	// Parse worker count
	if w := os.Getenv("ENRICHER_WORKERS"); w != "" {
		if val, err := strconv.Atoi(w); err == nil && val > 0 {
			numWorkers = val
		} else {
			log.Printf("[!] Invalid ENRICHER_WORKERS value '%s', falling back to default %d\n", w, numWorkers)
		}
	}

	// Parse buffer size
	if b := os.Getenv("ENRICHER_BUFFER_SIZE"); b != "" {
		if val, err := strconv.Atoi(b); err == nil && val > 0 {
			channelBufferSize = val
		} else {
			log.Printf("[!] Invalid ENRICHER_BUFFER_SIZE value '%s', falling back to default %d\n", b, channelBufferSize)
		}
	}
}

func main() {
	flag.Parse()
	if *eve_file == "" {
		log.Fatal("Usage: ./enricher -eve /path/to/eve.json_or_socket")
	}

	if *timescale == "" {
		*timescale = os.Getenv("TIMESCALE")
	}

	log.Println("Connecting to Timescale:", *timescale, "...")
	g_db = db.NewDatabase(*timescale)

	// Check environment variable for operational mode
	mode := os.Getenv("ENRICHER_MODE")

	if mode == "socket" {
		log.Println("Starting in SOCKET mode with Worker Pool...")
		watchEveSocket(*eve_file)
	} else {
		log.Println("Starting in FILE mode...")
		watchEveFile(*eve_file)
	}
}

// Worker that handles an eve line
func worker(id int, jobs <-chan string) {
	log.Printf("Worker %d started", id)
	for jsonLine := range jobs {
		err := handleEveLine(jsonLine)
		if err != nil {
			log.Printf("[Worker %d] Error parsing eve line: %s\n", id, err)
		}
	}
}

// Read alerts from a socket, instead of a file
// To make sure that all alerts read from the socket are processed, a
// worker architecture parallelizes the addition of tags in the timescaledb
func watchEveSocket(socket_path string) {
	log.Println("Starting Unix Socket Server at: ", socket_path)

	// Clean up dead socket
	os.Remove(socket_path)

	// Bind and Listen
	listener, err := net.Listen("unix", socket_path)
	if err != nil {
		log.Fatal("Failed to bind to socket:", err)
	}
	defer listener.Close()

	os.Chmod(socket_path, 0777)

	// Create the buffered channel (The Queue)
	jobChannel := make(chan string, channelBufferSize)

	// Telemetry Worker: Monitors queue depth every 5 seconds
	go func() {
		log.Printf("Booting Worker Pool: %d Workers, Buffer Capacity: %d\n", numWorkers, channelBufferSize)
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			currentDepth := len(jobChannel)
			capacity := cap(jobChannel)
			usage := float64(currentDepth) / float64(capacity) * 100
			
			// Only spam the logs if the buffer is starting to fill up
			if usage > 10 {
				log.Printf("[!] BUFFER WARNING: Queue is %.1f%% full (%d/%d alerts waiting). Consider increasing the number of workers/size of the buffer", usage, currentDepth, capacity)
			}
		}
	}()

	// Boot up the Worker Pool
	for w := 1; w <= numWorkers; w++ {
		go worker(w, jobChannel)
	}

	// Accept connections
	for {
		log.Println("Waiting for Suricata to connect...")
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		log.Println("Suricata connected! Reading stream...")
		reader := bufio.NewReader(conn)

		// Read the stream
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					log.Println("Suricata disconnected (EOF).")
				} else {
					log.Println("Error reading from stream:", err)
				}
				break
			}

			jobChannel <- line
		}
		conn.Close()
	}
}

// File mode for parsing eve.json alerts
func watchEveFile(eve_file string) {
	log.Println("Parsing initial eve contents...")
	ratchet := updateEve(eve_file, 0)

	log.Println("Monitoring eve file: ", eve_file)
	stat, err := os.Stat(eve_file)
	prevSize := int64(0)
	if err == nil {
		prevSize = stat.Size()
	}

	for {
		time.Sleep(time.Duration(*rescan_period) * time.Second)

		new_stat, err := os.Stat(eve_file)
		if err != nil {
			log.Println("Failed to open the eve file with error: ", err)
			continue
		}

		if new_stat.Size() > prevSize {
			log.Println("Eve file was updated. New size:, ", new_stat.Size())
			ratchet = updateEve(eve_file, ratchet)
		}
		prevSize = new_stat.Size()
	}
}

func updateEve(eve_file string, ratchet int64) int64 {
	eve_handle, err := os.Open(eve_file)
	if err != nil {
		log.Println("Failed to open the eve file")
		return ratchet
	}
	eve_handle.Seek(ratchet, 0)
	eve_reader := bufio.NewReader(eve_handle)
	defer eve_handle.Close()

	log.Println("Start scanning eve file at offset", ratchet)

	for {
		line, err := eve_reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading eve at offset %d: %s\n", ratchet, err)
			break
		}

		err = handleEveLine(line)

		if err == nil {
			ratchet += int64(len(line))
		}
		if err != nil {
			log.Printf("Error parsing eve at offset %d: %s\n", ratchet, err)
			ratchet += int64(len(line))
		}
	}
	return ratchet
}

func handleEveLine(json string) error {
	if !gjson.Valid(json) {
		return errors.New("Invalid json in eve line")
	}

	src_port := gjson.Get(json, "src_port")
	src_ip := gjson.Get(json, "src_ip")
	dst_port := gjson.Get(json, "dest_port")
	dst_ip := gjson.Get(json, "dest_ip")
	start_time := gjson.Get(json, "flow.start")

	sig_msg := gjson.Get(json, "alert.signature")
	sig_id := gjson.Get(json, "alert.signature_id")
	sig_action := gjson.Get(json, "alert.action")
	sig_tags := gjson.Get(json, "alert.metadata.tag")
	flowbits := gjson.Get(json, "metadata.flowbits")

	ip_src, _ := netip.ParseAddr(src_ip.String())
	ip_dst, _ := netip.ParseAddr(dst_ip.String())

	start_time_obj, _ := time.Parse("2006-01-02T15:04:05.999999999-0700", start_time.String())

	if !(sig_action.Exists() || (flowbits.Exists() && *tag_flowbits)) {
		return nil
	}

	var flow_id uuid.UUID
	max_retries := 30

	for i := 0; i < max_retries; i++ {
		flow_id, _ = g_db.SuricataIdFindFlow(db.SuricataId{
			Src_port: int(src_port.Int()),
			Src_ip:   ip_src,
			Dst_port: int(dst_port.Int()),
			Dst_ip:   ip_dst,
			Time:     start_time_obj,
		})

		if flow_id == uuid.Nil {
			flow_id, _ = g_db.SuricataIdFindFlow(db.SuricataId{
				Dst_port: int(src_port.Int()),
				Dst_ip:   ip_src,
				Src_port: int(dst_port.Int()),
				Src_ip:   ip_dst,
				Time:     start_time_obj,
			})
		}

		if flow_id != uuid.Nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	if flow_id == uuid.Nil {
		// Log spam prevention: only print failures, not skips
		log.Printf("Failed to tag flow: DB lookup failed after %d seconds of retries.", max_retries)
		return nil
	}

	tags := []string{}
	if sig_tags.Exists() {
		sig_tags.ForEach(func(key, value gjson.Result) bool {
			tags = append(tags, value.String())
			return true
		})
	}

	if sig_action.Exists() {
		sig := db.Signature{
			Id:      int32(sig_id.Int()),
			Message: sig_msg.String(),
			Action:  sig_action.String(),
		}

		tags = append(tags, "suricata")
		if sig.Action == "blocked" {
			tags = append(tags, "blocked")
		}

		g_db.FlowAddSignatures(flow_id, []db.Signature{sig})
	}

	if flowbits.Exists() && *tag_flowbits {
		flowbits.ForEach(func(key, value gjson.Result) bool {
			tags = append(tags, value.String())
			return true
		})
	}

	g_db.FlowAddTags(flow_id, tags)

	if len(tags) > 0 {
		log.Println("Applied", tags, "tags to flow", flow_id)
	}

	return nil
}
