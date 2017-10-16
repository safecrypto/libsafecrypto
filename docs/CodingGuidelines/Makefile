basename=coding
filename=$(basename).tex

all:
	pdflatex ${filename}
	bibtex ${basename}||true
	pdflatex ${filename}
	pdflatex ${filename}

clean:
	rm -f ${basename}.{ps,pdf,log,aux,out,dvi,bbl,blg} *.aux $(basename).pdf
