PLUGIN_NAME := nginxlog

all: $(PLUGIN_NAME)

$(PLUGIN_NAME):
	go build -buildmode=c-shared -o lib$(PLUGIN_NAME).so ./pkg

clean:
	rm -f lib$(PLUGIN_NAME).so
