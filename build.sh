source VERSION
sed -e 's#{VERSION}#'"${VERSION}"'#g' setup_template.py > setup.py

rm -R build/
python3 setup.py build sdist bdist_wheel

pdocs as_html --overwrite pumpwood_communication --output_dir docs
pdocs as_markdown --overwrite pumpwood_communication --outut_dir docs

git add --all
git commit -m "Building a new version ${VERSION}"
git tag -a ${VERSION} -m "Building a new version ${VERSION}"
git push
git push origin ${VERSION}
