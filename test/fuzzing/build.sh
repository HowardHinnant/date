#!/bin/bash -eu

# Performs the necessary steps to build the fuzz harnesses utilized to prepare the test library for fuzz-test
# integration into OSSFuzz

cd "$SRC"/date
mkdir -p build
cmake -S. -B build -DENABLE_FUZZ_TESTING=ON -DBUILD_TZ_LIB=OFF -DBUILD_SHARED_LIBS=OFF
cmake --build build --target install

# Compress the corpus to the $OUT directory
zip -q $WORK/seed_corpus.zip test/fuzzing/corpus/*

# Create a copy of the corpus in the $OUT directory for each target
for file in $(find "$OUT" -type f -regex ".*fuzz_.*")
do
  target=$(basename -- "$file")
  echo "Zipping corpus for target $target"
  cp $WORK/seed_corpus.zip $OUT/"$target"_seed_corpus.zip
done