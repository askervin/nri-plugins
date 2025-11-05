ifeq ($(DEBUG),1)
CFLAGS += -O0 -g -fsanitize=address -DDEBUG -Wall -Wextra
else
CFLAGS += -O2
endif

in-place-scaling: in-place-scaling.c
	gcc $(CFLAGS) -o $@ $< -lm

clean:
	$(RM) in-place-scaling
