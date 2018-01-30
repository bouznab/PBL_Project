library(lattice)

csvDataFrame <- read.table("iperf_plot.csv",header=TRUE)

print(csvDataFrame)
trellis.device("pdf", file="iperf.pdf", color=T, width=6.5, height=5.0)

xyplot(retry ~ time, csvDataFrame, type=c("p","g","o"))
