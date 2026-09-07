"""Reusable Streamlit map for visualising ordered email relay coordinates.

The public input intentionally mirrors the GeoIP handoff from Member 3:
``[(latitude, longitude), ...]``.
"""

from __future__ import annotations

from collections.abc import Sequence

import streamlit as st


Coordinate = tuple[float, float]

# Marker colors distinguish stage-in-route (origin / relay / destination)
# rather than implying danger. Red is intentionally reserved for the threat
# indicators shown elsewhere in the dashboard.
_ORIGIN_COLOR = [86, 230, 187]       # teal-green
_RELAY_COLOR = [22, 214, 232]        # cyan
_DESTINATION_COLOR = [255, 176, 32]  # amber


def render_hop_path_map(coordinates: Sequence[Coordinate]) -> None:
    """Render ordered hop markers and a connecting path for latitude/longitude pairs.

    An empty list displays an informative placeholder. A single coordinate shows
    one marker, while two or more coordinates additionally render a path in the
    exact supplied order. The first coordinate is labelled "Origin" and the
    last "Destination"; anything in between is labelled by hop number.
    """
    if not coordinates:
        st.info("No relay coordinates are available yet.")
        return

    try:
        import pydeck as pdk
    except ImportError:
        st.error("Map support requires pydeck. Install dependencies from frontend/requirements.txt.")
        return

    total = len(coordinates)

    def _label(index: int) -> str:
        if index == 1:
            return "Origin"
        if index == total:
            return "Destination"
        return f"Hop {index - 1}"

    def _color(index: int) -> list[int]:
        if index == 1:
            return _ORIGIN_COLOR
        if index == total:
            return _DESTINATION_COLOR
        return _RELAY_COLOR

    points = [
        {
            "position": [longitude, latitude],
            "hop": _label(index),
            "fill_color": _color(index),
        }
        for index, (latitude, longitude) in enumerate(coordinates, start=1)
    ]
    center_latitude = sum(latitude for latitude, _ in coordinates) / len(coordinates)
    center_longitude = sum(longitude for _, longitude in coordinates) / len(coordinates)
    layers = [
        pdk.Layer(
            "ScatterplotLayer",
            points,
            get_position="position",
            get_radius=125000,
            get_fill_color="fill_color",
            get_line_color=[235, 248, 255],
            line_width_min_pixels=1,
            pickable=True,
        ),
        pdk.Layer(
            "TextLayer",
            points,
            get_position="position",
            get_text="hop",
            get_size=15,
            get_color=[235, 248, 255],
            get_text_anchor="middle",
            get_alignment_baseline="bottom",
        ),
    ]
    if len(points) > 1:
        layers.insert(
            0,
            pdk.Layer(
                "PathLayer",
                [{"path": [point["position"] for point in points]}],
                get_path="path",
                get_color=[22, 214, 232],
                width_scale=20,
                width_min_pixels=3,
                pickable=False,
            ),
        )

    deck = pdk.Deck(
        map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json",
        initial_view_state=pdk.ViewState(
            latitude=center_latitude,
            longitude=center_longitude,
            zoom=2.3 if len(points) > 1 else 5,
            pitch=20,
        ),
        layers=layers,
        tooltip={"html": "<b>{hop}</b>", "style": {"backgroundColor": "#07111d", "color": "#eaf6ff"}},
    )
    st.pydeck_chart(deck, use_container_width=True, height=440)