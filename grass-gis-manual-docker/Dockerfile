FROM osgeo/grass-gis:main-alpine

ARG ADDON_NAME
ARG GITHUB_REPOSITORY

RUN apk add gcc linux-headers make musl-dev pandoc python3-dev

WORKDIR /src
COPY . /src

# create environment to install requirements
RUN python -m venv --system-site-packages addon-env
ENV PATH="/src/addon-env/bin:$PATH"
# --system-site-packages only works for active virtual environment.
# To use paths, below hack is needed..
RUN export VERSION=$(python -c \
    "import sys;print(f\"python{sys.version_info.major}.{sys.version_info.minor}\")"); \
    echo "/usr/lib/$VERSION/site-packages/" > /src/addon-env/lib/$VERSION/site-packages/system-packages.pth
RUN test -e requirements.txt && pip3 install -r requirements.txt || echo "No requirements.txt"

# Compile GRASS GIS addon
RUN grass --tmp-project XY --exec g.extension extension=${ADDON_NAME} url=. prefix=build --verbose
RUN mv build/docs/html/${ADDON_NAME}.html build/docs/html/index.html

# Reset URL (for multi-addon in all html files)
RUN for HTML in $(ls -d /src/build/docs/html/*.html) ; do sed -i "s+file:///usr/local/grass84/docs/html/+https://grass.osgeo.org/grass-stable/manuals/+g" ${HTML} ; done
RUN for HTML in $(ls -d /src/build/docs/html/*.html) ; do sed -i "s+(<a href=\"\">history</a>)+(<a href=\"https://github.com/${GITHUB_REPOSITORY}/commits/main/\">history</a>)+g" ${HTML} ; done
RUN for HTML in $(ls -d /src/build/docs/html/*.html) ; do sed -i "s+<a href=\"\">+<a href=\"https://github.com/${GITHUB_REPOSITORY}\">+g" ${HTML} ; done

# Reset URLs for multi-addons in index html
RUN for DIR in $(ls -d /src/*/) ; do for HTML in $(ls -d /src/build/docs/html/*.html) ; do SUB_ADDON=$(basename $DIR) ; sed -i "s+https://grass.osgeo.org/grass-stable/manuals/${SUB_ADDON}.html\">+https://mundialis.github.io/${ADDON_NAME}/${SUB_ADDON}.html\">+g" ${HTML} ; done ; done
RUN for DIR in $(ls -d /src/*/) ; do for HTML in $(ls -d /src/build/docs/html/*.html) ; do SUB_ADDON=$(basename $DIR) ; sed -i "s+https://grass.osgeo.org/grass-stable/manuals/${SUB_ADDON}/${SUB_ADDON}.html\">+https://mundialis.github.io/${ADDON_NAME}/${SUB_ADDON}.html\">+g" ${HTML} ; done ; done
