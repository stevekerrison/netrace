CC			= gcc
CFLAGS		= -Wall -O3 -c -g -flto
ifdef ver
	ifeq "$(ver)" "debug"
		CFLAGS += -DDEBUG_ON
	endif
endif
SOURCES		= netrace.c queue.c main.c
OBJECTS		= $(SOURCES:.c=.o)
EXECUTABLE	= main
LIBS            = -lm

all: $(SOURCES) $(EXECUTABLE)

python: netrace.o netrace.i setup.py
	swig -python netrace.i
	python setup.py build_ext --inplace

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(INCLUDES) $(LIBRARIES) $(OBJECTS) -o $(EXECUTABLE) $(LIBS)

netrace.o: $(SOURCES)
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE $(INCLUDES) $(LIBRARIES) $< -o $@ $(LIBS)

.o: $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBRARIES) $< -o $@ $(LIBS)

.c:
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBRARIES) $< -o $@ $(LIBS)

clean:
	rm -f $(EXECUTABLE) *.o
