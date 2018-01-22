library(lattice)

files <- list.files(pattern=".csv")
dataframe <- NULL
for(f in files){
    csvDataFrameSource <- read.table(f,header=TRUE)
    dataframe <- rbind(dataframe,csvDataFrameSource)
}

trellis.device("pdf", file="ping.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ ping, group=port, data=dataframe,
       type=c("p","g","o"), pch=8, auto.key=TRUE )

dev.off() -> null
