---
layout: archive
permalink: /writeups/
title: "CTF Challenge Writeups"
header:
  overlay_image: /assets/images/writeups-splash.jpg
  overlay_filter: 0.7
  caption: "Photo credit: Andre Benz on Unsplash"
excerpt: "Writeups written by the Nandy Narwhals team."
author_profile: true
---

{% include base_path %}
{% include group-by-array collection=site.posts field="tags" %}

{% for tag in group_names %}
  {% if tag == "writeup" %}
    {% assign posts = group_items[forloop.index0] %}
    {% for post in posts %}
      {% include archive-single.html %}
    {% endfor %}
  {% endif %}
{% endfor %}
