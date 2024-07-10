source VERSION
sed -e 's#{VERSION}#'"${VERSION}"'#g' setup_template.py > setup.py

rm -R build/
python3 setup.py build sdist bdist_wheel

pdoc --docformat="google" pumpwood_communication -o ./docs

git add --all
git commit -m "Building a new version ${VERSION}"
git tag -a ${VERSION} -m "Building a new version ${VERSION}"
git push
git push origin ${VERSION}
