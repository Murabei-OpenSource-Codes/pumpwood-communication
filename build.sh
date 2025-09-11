# Update version path
VERSION_FILE="VERSION"
current_version=$(grep -E "^VERSION=" "$VERSION_FILE" | cut -d'=' -f2)
IFS='.' read -r major minor patch <<< "$current_version"
patch=$((patch + 1))
new_version="$major.$minor.$patch"
sed -i "s/^VERSION=.*/VERSION=$new_version/" "$VERSION_FILE"
echo "Updated version to $new_version"

source VERSION
sed -e 's#{VERSION}#'"${VERSION}"'#g' setup_template.py > setup.py

rm -R build/
python3 setup.py build sdist bdist_wheel

# pdoc --docformat="google" src/pumpwood_communication -o ./docs

git add --all
git commit -m "Building a new version ${VERSION}"
git tag -a ${VERSION} -m "Building a new version ${VERSION}"
git push
git push origin ${VERSION}
