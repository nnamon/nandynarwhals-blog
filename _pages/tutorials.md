---
layout: archive
permalink: /tutorials/
title: "Tutorials"
header:
  overlay_image: /assets/images/tutorials-splash.jpg
  overlay_filter: 0.7
  caption: "Photo credit: Samuel Zeller on Unsplash"
excerpt: "Tutorials written by the Nandy Narwhals team."
author_profile: true
---

{% include base_path %}
{% include group-by-array collection=site.posts field="tags" %}

<h3 class="archive__subtitle">Scripting for CTFs</h3>

{% for tag in group_names %}
  {% if tag == "scriptingforctfs" %}
    {% assign posts = group_items[forloop.index0] %}
    {% for post in posts %}
      {% include archive-single.html %}
    {% endfor %}
  {% endif %}
{% endfor %}

