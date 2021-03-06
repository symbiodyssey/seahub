define([
    'underscore',
    'backbone',
    'common'
], function(_, Backbone, Common) {
    'use strict';

    var Collection = Backbone.Collection.extend({

        initialize: function(options) {
            this.repo_id = options.repo_id;
        },

        url: function() {
            return Common.getUrl({
                name: 'repo_group_folder_perm',
                repo_id: this.repo_id
            });
        }
    });

    return Collection;
});
