%.txt: %.sr
	/media/extradisk/adodd/emount/sigrok_data/decode_emount.sh $< &> $@

all: $(subst .sr,.txt,$(wildcard *.sr))
