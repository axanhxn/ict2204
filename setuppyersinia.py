from os.path import dirname, join
from setuptools import setup, find_packages

# Import requirements
with open(join(dirname(__file__), 'requirements.txt')) as f:
    required = f.read().splitlines()


setup(
    name='pyersinia',
    version='1.0.5',
    install_requires=required,
    url='https://github.com/nottinghamprisateam/pyersinia',
    license='BSD',
    author='Nottingham Prisa Team',
    author_email='pyersinia94@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    entry_points={'console_scripts': [
        'pyersinia = pyersinia_lib.pyersinia:main',
        ]},
    description='Herramienta para ataques de capa de enlace',
    long_description=open('README.md', "r").read(),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        ]
)
