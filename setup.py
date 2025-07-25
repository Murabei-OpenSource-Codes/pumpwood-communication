"""setup."""
import os
import setuptools
# try:  # for pip >= 10
#     from pip._internal.req import parse_requirements
# except ImportError:  # for pip <= 9.0.3
#     from pip.req import parse_requirements


with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

requirements_path = os.path.join(
    os.path.dirname(__file__), 'requirements.txt')
# install_reqs = parse_requirements(requirements_path, session=False)
# try:
#     requirements = [str(ir.req) for ir in install_reqs]
# except Exception:
#     requirements = [str(ir.requirement) for ir in install_reqs]


# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setuptools.setup(
    name='pumpwood-communication',
    version='2.2.10',
    include_package_data=True,
    license='BSD-3-Clause License',
    description='Package for inter Pumpwood loging and comunication',
    long_description=README,
    long_description_content_type="text/markdown",
    url='https://github.com/Murabei-OpenSource-Codes/pumpwood-communication',
    author='André Andrade Baceti',
    author_email='a.baceti@murabei.com',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    install_requires=[
        "requests",
        "simplejson",
        "pandas",
        "Shapely>=1.7.0",
        "geopandas>=0.8.1",
        "SQLAlchemy-Utils==0.37.8",
        "SQLAlchemy>=1.3.19",
        "GeoAlchemy2>=0.17.0",
        "apache-airflow-client==2.3.0",
        "requests>=2.28.2",
        "Werkzeug>=1.0.1",
    ],
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)
